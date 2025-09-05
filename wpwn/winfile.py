import lief

class PE:
    def __init__(self, path):
        self.pe = lief.PE.parse(path)
        self.address = self.pe.optional_header.imagebase
        exp = self.pe.get_export() if self.pe.has_exports else None
        self._exports = {}
        if exp:
            for e in exp.entries:
                if e.name:
                    self._exports[e.name.lower()] = e 

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

    def addr(self, name: str):
        e = self._exports.get(name.lower())
        if not e:
            raise KeyError(f"symbol not found: {name}")

        if getattr(e, "is_forwarded", False):
            fwd = getattr(e, "forward_information", None)
            return {"name": e.name, "forward": fwd or "<unknown>"}

        rva = getattr(e, "address", None)
        if rva is None:
            raise KeyError(f"no RVA for: {name}")

        off = self.pe.rva_to_offset(rva)
        va  = self.address + rva
        return {"name": e.name, "rva": rva, "va": va, "offset": off}

    def get_exports(self):
        out = []
        for e in self._exports.values():
            if getattr(e, "is_forwarded", False):
                out.append({"name": e.name, "forward": getattr(e, "forward_information", None)})
            else:
                rva = getattr(e, "address", None)
                off = self.pe.rva_to_offset(rva) if rva is not None else None
                va  = self.address + rva if rva is not None else None
                out.append({"name": e.name, "rva": rva, "va": va, "offset": off})
        return out

    def _iter_hits_in_section(self, sec, needle: bytes):
        if not needle:
            return
        data = bytes(sec.content)
        start = 0
        while True:
            idx = data.find(needle, start)
            if idx < 0:
                break
            rva = sec.virtual_address + idx
            yield rva
            start = idx + 1 

    def find_string(self, s, wide=False):
        if isinstance(s, bytes):
            needle = s
        else:
            needle = s.encode("utf-16le") if wide else s.encode("ascii", "ignore")
        for sec in self.pe.sections:
            for rva in self._iter_hits_in_section(sec, needle):
                yield self.address + rva

    def find_string_info(self, s, wide=False):
        if isinstance(s, bytes):
            needle = s
        else:
            needle = s.encode("utf-16le") if wide else s.encode("ascii", "ignore")
        for sec in self.pe.sections:
            for rva in self._iter_hits_in_section(sec, needle):
                yield {
                    "va": self.address + rva,
                    "rva": rva,
                    "section": sec.name,
                    "section_offset": rva - sec.virtual_address,
                }