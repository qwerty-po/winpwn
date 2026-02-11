import atexit
import ctypes
import pathlib
import struct
import tempfile
from ctypes import wintypes

import lief
import requests

MS_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def _guid_bytes_to_symserv(g: bytes) -> str:
    d1, d2, d3 = struct.unpack("<IHH", g[:8])
    d4 = g[8:]
    return f"{d1:08X}{d2:04X}{d3:04X}{d4.hex().upper()}"


class _DbgHelp:
    SYMOPT_UNDNAME = 0x00000002
    SYMOPT_DEFERRED_LOADS = 0x00000004
    SYMOPT_FAIL_CRITICAL_ERRORS = 0x00000200
    SYMOPT_NO_PROMPTS = 0x00080000
    SYMOPT_AUTO_PUBLICS = 0x00010000

    def __init__(self):
        self.dbghelp = ctypes.WinDLL("dbghelp.dll")
        self.kernel32 = ctypes.WinDLL("kernel32.dll")
        self._proc = self.kernel32.GetCurrentProcess()
        self._initialized = False
        self._modbase = 0

        self.dbghelp.SymSetOptions.argtypes = [wintypes.DWORD]
        self.dbghelp.SymSetOptions.restype = wintypes.DWORD

        self.dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
        self.dbghelp.SymInitializeW.restype = wintypes.BOOL

        self.dbghelp.SymCleanup.argtypes = [wintypes.HANDLE]
        self.dbghelp.SymCleanup.restype = wintypes.BOOL

        self.dbghelp.SymRefreshModuleList.argtypes = [wintypes.HANDLE]
        self.dbghelp.SymRefreshModuleList.restype = wintypes.BOOL

        self.dbghelp.SymLoadModuleExW.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.c_ulonglong,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self.dbghelp.SymLoadModuleExW.restype = ctypes.c_ulonglong

        self.dbghelp.SymUnloadModule64.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong]
        self.dbghelp.SymUnloadModule64.restype = wintypes.BOOL

        self.dbghelp.SymFromNameW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_void_p]
        self.dbghelp.SymFromNameW.restype = wintypes.BOOL

        self.dbghelp.SymGetModuleInfoW64.argtypes = [wintypes.HANDLE, ctypes.c_ulonglong, ctypes.c_void_p]
        self.dbghelp.SymGetModuleInfoW64.restype = wintypes.BOOL

        self.kernel32.GetLastError.argtypes = []
        self.kernel32.GetLastError.restype = wintypes.DWORD

        self.kernel32.SetEnvironmentVariableW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
        self.kernel32.SetEnvironmentVariableW.restype = wintypes.BOOL

        self.kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        self.kernel32.CreateFileW.restype = wintypes.HANDLE

        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL

    class SYMBOL_INFOW(ctypes.Structure):
        _fields_ = [
            ("SizeOfStruct", wintypes.ULONG),
            ("TypeIndex", wintypes.ULONG),
            ("Reserved", ctypes.c_ulonglong * 2),
            ("Index", wintypes.ULONG),
            ("Size", wintypes.ULONG),
            ("ModBase", ctypes.c_ulonglong),
            ("Flags", wintypes.ULONG),
            ("Value", ctypes.c_ulonglong),
            ("Address", ctypes.c_ulonglong),
            ("Register", wintypes.ULONG),
            ("Scope", wintypes.ULONG),
            ("Tag", wintypes.ULONG),
            ("NameLen", wintypes.ULONG),
            ("MaxNameLen", wintypes.ULONG),
            ("Name", wintypes.WCHAR * 1),
        ]

    class IMAGEHLP_MODULEW64(ctypes.Structure):
        _fields_ = [
            ("SizeOfStruct", wintypes.DWORD),
            ("BaseOfImage", ctypes.c_ulonglong),
            ("ImageSize", wintypes.DWORD),
            ("TimeDateStamp", wintypes.DWORD),
            ("CheckSum", wintypes.DWORD),
            ("NumSyms", wintypes.DWORD),
            ("SymType", wintypes.DWORD),
            ("ModuleName", wintypes.WCHAR * 32),
            ("ImageName", wintypes.WCHAR * 256),
            ("LoadedImageName", wintypes.WCHAR * 256),
            ("LoadedPdbName", wintypes.WCHAR * 256),
            ("CVSig", wintypes.DWORD),
            ("CVData", wintypes.WCHAR * 780),
            ("PdbSig", wintypes.DWORD),
            ("PdbSig70", ctypes.c_ubyte * 16),
            ("PdbAge", wintypes.DWORD),
            ("PdbUnmatched", wintypes.BOOL),
            ("DbgUnmatched", wintypes.BOOL),
            ("LineNumbers", wintypes.BOOL),
            ("GlobalSymbols", wintypes.BOOL),
            ("TypeInfo", wintypes.BOOL),
            ("SourceIndexed", wintypes.BOOL),
            ("Publics", wintypes.BOOL),
        ]

    def init(self, symbol_path: str):
        if self._initialized:
            return

        self.kernel32.SetEnvironmentVariableW("_NT_SYMBOL_PATH", symbol_path)
        self.kernel32.SetEnvironmentVariableW("NT_SYMBOL_PATH", symbol_path)

        opts = (
            self.SYMOPT_UNDNAME
            | self.SYMOPT_DEFERRED_LOADS
            | self.SYMOPT_FAIL_CRITICAL_ERRORS
            | self.SYMOPT_NO_PROMPTS
            | self.SYMOPT_AUTO_PUBLICS
        )
        self.dbghelp.SymSetOptions(opts)

        ok = self.dbghelp.SymInitializeW(self._proc, symbol_path, False)
        if not ok:
            raise RuntimeError(f"SymInitializeW failed: GetLastError={self.kernel32.GetLastError()}")
        self._initialized = True

    def refresh_modules(self):
        ok = self.dbghelp.SymRefreshModuleList(self._proc)
        if not ok:
            raise RuntimeError(f"SymRefreshModuleList failed: GetLastError={self.kernel32.GetLastError()}")

    def _open_file(self, path: str):
        h = self.kernel32.CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if ctypes.c_void_p(h).value == INVALID_HANDLE_VALUE:
            raise RuntimeError(f"CreateFileW failed: GetLastError={self.kernel32.GetLastError()}")
        return h

    def _close_file(self, h):
        if h and ctypes.c_void_p(h).value != INVALID_HANDLE_VALUE:
            self.kernel32.CloseHandle(h)

    def unload(self):
        if self._modbase:
            self.dbghelp.SymUnloadModule64(self._proc, ctypes.c_ulonglong(self._modbase))
            self._modbase = 0

    def load_module_offline(self, image_path: str, base: int = 0) -> int:
        self.unload()

        image_path = str(image_path)
        module_name = pathlib.Path(image_path).stem

        hfile = self._open_file(image_path)
        try:
            loaded = self.dbghelp.SymLoadModuleExW(
                self._proc,
                hfile,
                image_path,
                module_name,
                ctypes.c_ulonglong(base),
                0,
                None,
                0,
            )
            if loaded == 0:
                raise RuntimeError(f"SymLoadModuleExW failed: GetLastError={self.kernel32.GetLastError()}")
            self._modbase = int(loaded)
            return self._modbase
        finally:
            self._close_file(hfile)

    def module_info(self):
        if not self._modbase:
            return None
        mi = self.IMAGEHLP_MODULEW64()
        mi.SizeOfStruct = ctypes.sizeof(self.IMAGEHLP_MODULEW64)
        ok = self.dbghelp.SymGetModuleInfoW64(self._proc, ctypes.c_ulonglong(self._modbase), ctypes.byref(mi))
        if not ok:
            raise RuntimeError(f"SymGetModuleInfoW64 failed: GetLastError={self.kernel32.GetLastError()}")
        return {
            "ModBase": self._modbase,
            "ModuleName": mi.ModuleName,
            "ImageName": mi.ImageName,
            "LoadedImageName": mi.LoadedImageName,
            "LoadedPdbName": mi.LoadedPdbName,
            "CVData": mi.CVData,
            "PdbAge": int(mi.PdbAge),
            "PdbSig70": bytes(mi.PdbSig70),
        }

    def sym_rva_from_name(self, name: str) -> int:
        max_name = 4096
        buf_size = ctypes.sizeof(self.SYMBOL_INFOW) + (max_name * ctypes.sizeof(wintypes.WCHAR))
        raw = ctypes.create_string_buffer(buf_size)

        sym = ctypes.cast(raw, ctypes.POINTER(self.SYMBOL_INFOW)).contents
        sym.SizeOfStruct = ctypes.sizeof(self.SYMBOL_INFOW)
        sym.MaxNameLen = max_name

        ok = self.dbghelp.SymFromNameW(self._proc, name, raw)
        if not ok:
            raise KeyError(f"SymFromNameW('{name}') failed: GetLastError={self.kernel32.GetLastError()}")

        sym2 = ctypes.cast(raw, ctypes.POINTER(self.SYMBOL_INFOW)).contents
        addr = int(sym2.Address)
        modb = int(sym2.ModBase) or int(self._modbase)
        return addr - modb

    def cleanup(self):
        if self._initialized:
            self.dbghelp.SymCleanup(self._proc)
        self._initialized = False
        self._modbase = 0


class PE:
    def __init__(self, path):
        self.pe = lief.PE.parse(path)
        self._path = str(path)

        self.address = int(self.pe.optional_header.imagebase)

        exp = self.pe.get_export() if self.pe.has_exports else None
        self._exports = {}
        if exp:
            for e in exp.entries:
                if e.name:
                    self._exports[e.name.lower()] = e

        self._rsds = self._extract_rsds()

        self._dbg = None
        self._tmp = None
        self._sym_path = None
        self._symbols_ready = False
        self._pdb_local_path = None

        self._sym_rva_cache = {}
        self._cleaned = False

        atexit.register(self.cleanup)

    def cleanup(self):
        if self._cleaned:
            return
        self._cleaned = True
        try:
            if self._dbg:
                self._dbg.cleanup()
        except Exception:
            pass
        try:
            if self._tmp:
                self._tmp.cleanup()
        except Exception:
            pass

    def set_imagebase(self, imagebase: int):
        self.address = int(imagebase)

    def __getitem__(self, key):
        if key == "imagebase":
            return self.address
        if key == "entrypoint":
            return self.pe.rva_to_offset(self.pe.optional_header.addressof_entrypoint)
        if isinstance(key, str):
            info = self.addr(key)
            if "forward" in info:
                raise KeyError(f'forwarded export: {key} -> {info["forward"]}')
            return info["va"]
        raise KeyError(key)

    def _extract_rsds_lief(self):
        for d in self.pe.debug:
            if d.type != lief.PE.Debug.TYPES.CODEVIEW:
                continue

            if hasattr(d, "payload"):
                buf = bytes(d.payload)
                if len(buf) >= 24 and buf[:4] == b"RSDS":
                    guid = buf[4:20]
                    age = struct.unpack_from("<I", buf, 20)[0]
                    pdb_path = buf[24:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                    pdb_name = pathlib.Path(pdb_path).name
                    return pdb_name, guid, int(age)

            for pfield in ("path", "filename", "pdb_path", "pdb_filename"):
                if hasattr(d, pfield):
                    p = getattr(d, pfield)
                    if isinstance(p, bytes):
                        p = p.decode("utf-8", errors="replace")
                    if isinstance(p, str) and p:
                        pdb_name = pathlib.Path(p).name
                        break
            else:
                pdb_name = None

            guid = None
            for gfield in ("guid", "signature70", "pdb_signature70", "pdb_signature"):
                if hasattr(d, gfield):
                    g = getattr(d, gfield)
                    if isinstance(g, (bytes, bytearray)) and len(g) == 16:
                        guid = bytes(g)
                        break

            age = None
            for afield in ("age", "pdb_age"):
                if hasattr(d, afield) and isinstance(getattr(d, afield), int):
                    age = int(getattr(d, afield))
                    break

            if pdb_name and guid and age is not None:
                return pdb_name, guid, age

        return None

    def _extract_rsds_dbghelp_index(self):
        dbg = _DbgHelp()
        dbg.init("")  # no symbol path needed to read CV index from image
        dbg.refresh_modules()
        dbg.load_module_offline(self._path, base=0)
        dbg.refresh_modules()
        mi = dbg.module_info() or {}
        dbg.cleanup()

        guid = mi.get("PdbSig70", b"")
        age = mi.get("PdbAge", None)
        cv = mi.get("CVData", "")

        if isinstance(cv, bytes):
            cv = cv.decode("utf-8", errors="replace")
        if isinstance(cv, str):
            cv = cv.split("\x00", 1)[0]

        pdb_name = pathlib.Path(cv).name if cv else None

        if pdb_name and isinstance(guid, (bytes, bytearray)) and len(guid) == 16 and isinstance(age, int) and age != 0:
            return pdb_name, bytes(guid), int(age)

        return None

    def _extract_rsds(self):
        rsds = self._extract_rsds_lief()
        if rsds:
            return rsds
        rsds = self._extract_rsds_dbghelp_index()
        return rsds

    def _download_pdb_temp(self, timeout_sec: int = 60) -> str:
        if self._pdb_local_path:
            return self._pdb_local_path
        if not self._rsds:
            raise RuntimeError("No RSDS(CodeView) info found")

        pdb_name, guid, age = self._rsds
        guid_str = _guid_bytes_to_symserv(guid)
        key = f"{guid_str}{age:X}"
        url = f"{MS_SYMBOL_SERVER}/{pdb_name}/{key}/{pdb_name}"

        if not self._tmp:
            self._tmp = tempfile.TemporaryDirectory(prefix="pdb_")

        out_path = pathlib.Path(self._tmp.name) / pdb_name

        r = requests.get(url, stream=True, timeout=timeout_sec)
        if r.status_code != 200:
            raise RuntimeError(f"PDB download failed: HTTP {r.status_code} url={url}")

        with open(out_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)

        self._pdb_local_path = str(out_path)
        return self._pdb_local_path

    def _ensure_symbols_ready(self):
        if self._symbols_ready:
            return

        pdb_path = self._download_pdb_temp()
        sym_dir = str(pathlib.Path(pdb_path).parent)
        self._sym_path = sym_dir

        self._dbg = _DbgHelp()
        self._dbg.init(self._sym_path)
        self._dbg.refresh_modules()
        self._dbg.load_module_offline(self._path, base=0)
        self._dbg.refresh_modules()

        self._symbols_ready = True

    def rva(self, name: str) -> int:
        key = name.lower()

        e = self._exports.get(key)
        if e:
            rva = getattr(e, "address", None)
            if rva is None:
                raise KeyError(f"no RVA for: {name}")
            return int(rva)

        if key in self._sym_rva_cache:
            return self._sym_rva_cache[key]

        self._ensure_symbols_ready()

        stem = pathlib.Path(self._path).stem
        candidates = [name, f"{stem}!{name}"]

        last = None
        for n in candidates:
            try:
                rva = int(self._dbg.sym_rva_from_name(n))
                self._sym_rva_cache[key] = rva
                return rva
            except Exception as ex:
                last = ex

        raise KeyError(f"symbol not found: {name} ({last})")

    def addr(self, name: str):
        e: lief.PE.ExportEntry = self._exports.get(name.lower())
        if e and getattr(e, "is_forwarded", False):
            fwd = getattr(e, "forward_information", None)
            return {"name": e.name, "forward": fwd or "<unknown>"}

        rva = self.rva(name)
        off = self.pe.rva_to_offset(rva)
        va = self.address + rva
        return {"name": name, "rva": rva, "va": va, "offset": off}