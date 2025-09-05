import lief

class PE:
    def __init__(self, path):
        self.pe = lief.PE.parse(path)
        self.address = self.pe.optional_header.imagebase
        self._exports = {}
        if self.pe.has_exports:
            exp = self.pe.get_export()
            for e in exp.entries:
                if e.name:
                    self._exports[e.name] = e.address  

    def _rva_to_file_offset(self, rva):
        for s in self.pe.sections:
            va = s.virtual_address
            rsz = s.sizeof_raw_data or 0
            vsz = s.virtual_size or 0
            span = max(rsz, vsz)
            if va <= rva < va + span:
                return (rva - va) + (s.pointerto_raw_data or 0)
        return None

    def __getitem__(self, key):
        if key == "imagebase":
            return self.address
        if key == "entrypoint":
            return self._rva_to_file_offset(self.pe.optional_header.addressof_entrypoint)
        if key == "sections":
            return [s.name for s in self.pe.sections]
        if isinstance(key, str):
            rva = self._exports.get(key)
            if rva is None:
                raise KeyError(key)
            off = self._rva_to_file_offset(rva)
            if off is None:
                raise KeyError(key)
            return off
        raise KeyError(key)
            
