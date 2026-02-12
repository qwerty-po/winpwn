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


def _system32_path(dll_name: str) -> str:
    dll_name = dll_name.lower()
    if not dll_name.endswith(".dll"):
        dll_name += ".dll"
    return str(pathlib.Path(r"C:\Windows\System32") / dll_name)


def _is_apiset(name: str) -> bool:
    n = name.lower()
    return n.startswith("api-ms-") or n.startswith("ext-ms-")


class _DbgHelpGlobal:
    _inst = None

    @classmethod
    def inst(cls):
        if cls._inst is None:
            cls._inst = _DbgHelpGlobal()
        return cls._inst

    SYMOPT_UNDNAME = 0x00000002
    SYMOPT_DEFERRED_LOADS = 0x00000004
    SYMOPT_FAIL_CRITICAL_ERRORS = 0x00000200
    SYMOPT_NO_PROMPTS = 0x00080000
    SYMOPT_AUTO_PUBLICS = 0x00010000

    def __init__(self):
        self.dbghelp = ctypes.WinDLL("dbghelp.dll")
        self.kernel32 = ctypes.WinDLL("kernel32.dll")
        self.proc = self.kernel32.GetCurrentProcess()

        self.dbghelp.SymSetOptions.argtypes = [wintypes.DWORD]
        self.dbghelp.SymSetOptions.restype = wintypes.DWORD

        self.dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
        self.dbghelp.SymInitializeW.restype = wintypes.BOOL

        self.dbghelp.SymCleanup.argtypes = [wintypes.HANDLE]
        self.dbghelp.SymCleanup.restype = wintypes.BOOL

        self.dbghelp.SymSetSearchPathW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR]
        self.dbghelp.SymSetSearchPathW.restype = wintypes.BOOL

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

        self.dbghelp.SymFromNameW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_void_p]
        self.dbghelp.SymFromNameW.restype = wintypes.BOOL

        self.kernel32.GetLastError.argtypes = []
        self.kernel32.GetLastError.restype = wintypes.DWORD

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

        self._initialized = False
        self._search_dirs = []
        self._modbase_by_path = {}

        self._next_base = 0x0000000200000000  # 8GB
        self._base_step = 0x00200000          # 2MB

        atexit.register(self.cleanup)

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

    def ensure_init(self):
        if self._initialized:
            return
        opts = (
            self.SYMOPT_UNDNAME
            | self.SYMOPT_DEFERRED_LOADS
            | self.SYMOPT_FAIL_CRITICAL_ERRORS
            | self.SYMOPT_NO_PROMPTS
            | self.SYMOPT_AUTO_PUBLICS
        )
        self.dbghelp.SymSetOptions(opts)
        ok = self.dbghelp.SymInitializeW(self.proc, "", False)
        if not ok:
            raise RuntimeError(f"SymInitializeW failed: GetLastError={self.kernel32.GetLastError()}")
        self._initialized = True

    def add_search_dir(self, d: str):
        self.ensure_init()
        d = str(d)
        if d in self._search_dirs:
            return
        self._search_dirs.append(d)
        path = ";".join(self._search_dirs)
        ok = self.dbghelp.SymSetSearchPathW(self.proc, path)
        if not ok:
            raise RuntimeError(f"SymSetSearchPathW failed: GetLastError={self.kernel32.GetLastError()}")
        self.dbghelp.SymRefreshModuleList(self.proc)

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

    def load_offline_module(self, image_path: str) -> int:
        self.ensure_init()
        image_path = str(image_path)
        if image_path in self._modbase_by_path:
            return self._modbase_by_path[image_path]

        modname = pathlib.Path(image_path).stem

        base = self._next_base
        self._next_base += self._base_step

        hfile = self._open_file(image_path)
        try:
            loaded = self.dbghelp.SymLoadModuleExW(
                self.proc,
                hfile,
                image_path,
                modname,
                ctypes.c_ulonglong(base),
                0,
                None,
                0,
            )
            if loaded == 0:
                raise RuntimeError(f"SymLoadModuleExW failed: GetLastError={self.kernel32.GetLastError()} path={image_path}")
            modbase = int(loaded)
            self._modbase_by_path[image_path] = modbase
            return modbase
        finally:
            self._close_file(hfile)

    def sym_rva(self, module_path: str, symbol: str) -> int:
        module_path = str(module_path)
        modname = pathlib.Path(module_path).stem
        modbase = self.load_offline_module(module_path)

        query = f"{modname}!{symbol}"

        max_name = 4096
        buf_size = ctypes.sizeof(self.SYMBOL_INFOW) + (max_name * ctypes.sizeof(wintypes.WCHAR))
        raw = ctypes.create_string_buffer(buf_size)

        si = ctypes.cast(raw, ctypes.POINTER(self.SYMBOL_INFOW)).contents
        si.SizeOfStruct = ctypes.sizeof(self.SYMBOL_INFOW)
        si.MaxNameLen = max_name

        ok = self.dbghelp.SymFromNameW(self.proc, query, raw)
        if not ok:
            raise KeyError(f"SymFromNameW('{query}') failed: GetLastError={self.kernel32.GetLastError()}")

        si2 = ctypes.cast(raw, ctypes.POINTER(self.SYMBOL_INFOW)).contents
        addr = int(si2.Address)
        mb = int(si2.ModBase) or modbase
        return addr - mb

    def cleanup(self):
        if self._initialized:
            self.dbghelp.SymCleanup(self.proc)
        self._initialized = False
        self._search_dirs.clear()
        self._modbase_by_path.clear()


class PE:
    def __init__(self, path: str):
        self.pe = lief.PE.parse(path)
        if self.pe is None:
            raise RuntimeError(f"LIEF parse failed: {path}")

        self._path = str(path)
        self._mod = pathlib.Path(self._path).stem
        self.address = int(self.pe.optional_header.imagebase)

        exp = self.pe.get_export() if self.pe.has_exports else None
        self._exports = {}
        self._exports_by_ordinal = {}
        if exp:
            for e in exp.entries:
                if e.name:
                    self._exports[e.name.lower()] = e
                try:
                    self._exports_by_ordinal[int(e.ordinal)] = e
                except Exception:
                    pass

        self._imports = {}
        for imp in self.pe.imports:
            for entry in imp.entries:
                self._imports[entry.name] = entry

        self._rsds = self._extract_rsds()

        self._tmp = None
        self._pdb_local_dir = None
        self._sym_rva_cache = {}

        self._cleaned = False
        atexit.register(self.cleanup)

    def cleanup(self):
        if self._cleaned:
            return
        self._cleaned = True
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
                # now we resolve forward instead of raising
                return info["va"]
            return info["va"]
        raise KeyError(key)
    
    def imp(self, name: str) -> int:
        entry = self._imports.get(name)
        if not entry:
            raise KeyError(f"import not found: {name}")
        return self.address + entry.iat_address
    
    def _extract_rsds(self):
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

            pdb_name = None
            for pfield in ("path", "filename", "pdb_path", "pdb_filename"):
                if hasattr(d, pfield):
                    p = getattr(d, pfield)
                    if isinstance(p, bytes):
                        p = p.decode("utf-8", errors="replace")
                    if isinstance(p, str) and p:
                        pdb_name = pathlib.Path(p).name
                        break

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

    def _ensure_pdb_dir_added(self):
        if self._pdb_local_dir:
            return
        if not self._rsds:
            raise RuntimeError(f"No RSDS(CodeView) info found in {self._path}")

        pdb_name, guid, age = self._rsds
        guid_str = _guid_bytes_to_symserv(guid)
        key = f"{guid_str}{age:X}"
        url = f"{MS_SYMBOL_SERVER}/{pdb_name}/{key}/{pdb_name}"

        if not self._tmp:
            self._tmp = tempfile.TemporaryDirectory(prefix="pdb_")

        out_path = pathlib.Path(self._tmp.name) / pdb_name
        r = requests.get(url, stream=True, timeout=60)
        if r.status_code != 200:
            raise RuntimeError(f"PDB download failed: HTTP {r.status_code} url={url}")

        with open(out_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)

        self._pdb_local_dir = str(out_path.parent)
        _DbgHelpGlobal.inst().add_search_dir(self._pdb_local_dir)

    def _resolve_forward(self, fwd: str) -> int:
        # fwd examples:
        #   "KERNELBASE.Sleep"
        #   "ntdll.RtlAllocateHeap"
        #   "api-ms-win-core-synch-l1-2-0.Sleep"
        #   "KERNELBASE.#123"
        fwd = fwd.strip()
        if not fwd:
            raise KeyError("empty forward")

        if "." not in fwd:
            raise KeyError(f"bad forward: {fwd}")

        dll, sym = fwd.split(".", 1)
        dll = dll.strip()
        sym = sym.strip()

        # ordinal forward
        if sym.startswith("#"):
            # We can only resolve ordinal if we can open the target DLL and it has that ordinal exported.
            ordv = int(sym[1:])
            target_paths = []
            if _is_apiset(dll):
                # best-effort fallback for apiset forwards
                target_paths += [_system32_path("kernelbase"), _system32_path("ntdll")]
            else:
                target_paths.append(_system32_path(dll))

            for tp in target_paths:
                try:
                    pe_t = PE(tp)
                    e = pe_t._exports_by_ordinal.get(ordv)
                    if not e:
                        continue
                    rva = int(getattr(e, "address", 0))
                    return pe_t.address + rva
                except Exception:
                    continue

            raise KeyError(f"forward ordinal not resolved: {fwd}")

        # name forward
        target_paths = []
        if _is_apiset(dll):
            target_paths += [_system32_path("kernelbase"), _system32_path("ntdll")]
        else:
            target_paths.append(_system32_path(dll))

        for tp in target_paths:
            try:
                pe_t = PE(tp)
                return pe_t["" + sym]
            except Exception:
                continue

        raise KeyError(f"forward not resolved: {fwd}")

    def rva(self, name: str) -> int:
        key = name.lower()

        e = self._exports.get(key)
        if e:
            # forwarded export => resolve to target and convert to RVA relative to THIS module? Not meaningful.
            # For caller, we want final VA, so handle in addr().
            rva = getattr(e, "address", None)
            if rva is None:
                raise KeyError(f"no RVA for: {name}")
            return int(rva)

        if key in self._sym_rva_cache:
            return self._sym_rva_cache[key]

        self._ensure_pdb_dir_added()
        g = _DbgHelpGlobal.inst()
        rva = int(g.sym_rva(self._path, name))
        self._sym_rva_cache[key] = rva
        return rva

    def addr(self, name: str):
        e: lief.PE.ExportEntry = self._exports.get(name.lower())
        if e and getattr(e, "is_forwarded", False):
            fwd = getattr(e, "forward_information", None) or ""
            va = self._resolve_forward(fwd)
            return {"name": e.name, "forward": fwd, "va": va}

        rva = self.rva(name)
        off = self.pe.rva_to_offset(rva)
        va = self.address + rva
        return {"name": name, "rva": rva, "va": va, "offset": off}