"""Persistent IDA identities and kernel xrefs for Wasm runtime globals.

The private BSS segment is an analysis model of globals, not Wasm linear memory
and not the encoded variable-length initializer bytes in the input file.
"""
import hashlib
import json

import ida_bytes
import ida_ida
import ida_idaapi
import ida_name
import ida_loader
import ida_ua
import ida_segment
import ida_typeinf
import ida_xref
import idautils

from .binary import WasmError
from .references import collect_references

SEGMENT = '.wasm_globals'
MARKER = 'wasm-decompiler runtime global identities v1'


def read_blob(node,tag):
    data = node.getblob(0,tag)
    return json.loads(data.decode('utf-8')) if data else {}


def save_blob(node,tag,value):
    node.setblob(json.dumps(value,separators=(',',':')).encode('utf-8'),0,tag)


class DatabaseSymbols:
    def __init__(self, session):
        self.session = session
        self.node = session.node
        self.segment_name = read_blob(self.node,'G').get('segment')
        self._digest = None
        self._module = None
        self.diagnostics = []
        self.ensure_globals()

    def ensure_globals(self):
        globals_ = self.session.base.globals
        if not globals_:
            return
        segment = ida_segment.get_segm_by_name(self.segment_name) if self.segment_name else None
        if segment and ida_segment.get_segment_cmt(segment,True) != MARKER:
            raise WasmError('saved global identity segment has been replaced')
        if segment:
            if segment.size() < len(globals_)*8:
                raise WasmError('saved global identity segment is too small')
            return
        name = SEGMENT
        suffix = 1
        while ida_segment.get_segm_by_name(name):
            name = f'{SEGMENT}_{suffix}'
            suffix += 1
        size = (len(globals_)*8+0xfff) & ~0xfff
        start = ida_bytes.find_free_chunk(ida_ida.inf_get_max_ea(),size,0xfff)
        if start == ida_idaapi.BADADDR:
            raise WasmError('could not allocate global identities')
        if not ida_segment.add_segm(0,start,start+size,name,'BSS',ida_segment.ADDSEG_NOSREG):
            raise WasmError('could not create global identity segment')
        segment = ida_segment.getseg(start)
        ida_segment.set_segment_cmt(segment,MARKER,True)
        self.segment_name = name
        save_blob(self.node,'G',dict(segment=name))
        type_ids = {'i32':ida_typeinf.BTF_UINT32,'i64':ida_typeinf.BTF_UINT64,
                    'f32':ida_typeinf.BTF_FLOAT,'f64':ida_typeinf.BTF_DOUBLE}
        for i,g in enumerate(globals_):
            ea,width = start+i*8,int(g['type'][1:])//8
            init = g.get('init')
            if init and init[0] != 'global':
                n = init[1]
                data = (n & ((1<<(width*8))-1)).to_bytes(width,'little') if isinstance(n,int) else bytes(n)
                ida_bytes.put_bytes(ea,data)
            flag = {'i32':ida_bytes.FF_DWORD,'i64':ida_bytes.FF_QWORD,
                    'f32':ida_bytes.FF_FLOAT,'f64':ida_bytes.FF_DOUBLE}[g['type']]
            ida_bytes.create_data(ea,flag,width,ida_idaapi.BADADDR)
            ida_typeinf.apply_tinfo(ea,ida_typeinf.tinfo_t(type_ids[g['type']]),ida_typeinf.TINFO_DEFINITE)
            name = f'global_{i}'
            if ida_name.get_name_ea(ida_idaapi.BADADDR,name) != ida_idaapi.BADADDR:
                name = f'wasm_global_{i}'
            if not ida_name.set_name(ea,name,ida_name.SN_CHECK):
                ida_name.set_name(ea,f'wasm_runtime_global_{i}',ida_name.SN_FORCE)
            comment = f'Wasm runtime global #{i}; {g["type"]}; '+('mutable' if g['mutable'] else 'immutable')
            if g['imported']:
                comment += '; imported, initial value unknown'
            else:
                comment += f'; initializer {init!r}'
            ida_bytes.set_cmt(ea,comment,True)

    def global_ea(self, index):
        if not 0 <= index < len(self.session.module.globals):
            return ida_idaapi.BADADDR
        segment = ida_segment.get_segm_by_name(self.segment_name)
        return segment.start_ea+index*8 if segment else ida_idaapi.BADADDR

    def function_ea(self,index):
        function = self.session.module.functions[index]
        if not function.imported:
            return self.session.ea(function.code_offset)
        # Built-in loader import names may have processor-specific decorations.
        # Never map an imported function to byte zero as if it had a body.
        return ida_name.get_name_ea(ida_idaapi.BADADDR,function.name) if function.name else ida_idaapi.BADADDR

    def ensure_index(self,cancelled=lambda:False):
        layout = [self.global_ea(0) if self.session.module.globals else None,
                  self.session.ea(0)]
        if self._module is self.session.module and self._digest and self._digest[1] == layout:
            return
        digest = hashlib.sha256(self.session.module.data).hexdigest()
        key = [digest,layout,2]
        previous = read_blob(self.node,'R')
        if previous.get('key') == key:
            self._digest, self._module = key, self.session.module
            return
        references,self.diagnostics = collect_references(self.session.module,cancelled)
        if cancelled():
            raise WasmError('cross-reference indexing cancelled',code='cancelled')
        # All decoding completes before modifying existing refs. Only refs created
        # by this plugin are replaced; existing user/loader refs remain untouched.
        for offset,kind,index in previous.get('owned',[]):
            source = self.session.ea(offset)
            target = self.function_ea(index) if kind=='call' else self.global_ea(index)
            if source != ida_idaapi.BADADDR and target != ida_idaapi.BADADDR:
                if kind == 'call':
                    ida_xref.del_cref(source,target,False)
                else:
                    ida_xref.del_dref(source,target)
        owned = []
        normalized = {}
        for offset,kind,index in references:
            source = self.session.ea(offset)
            target = self.function_ea(index) if kind=='call' else self.global_ea(index)
            if source == ida_idaapi.BADADDR or target == ida_idaapi.BADADDR:
                continue
            flags = ida_bytes.get_full_flags(source)
            if ida_bytes.is_unknown(flags):
                ida_ua.create_insn(source)
                flags = ida_bytes.get_full_flags(source)
            if ida_bytes.is_tail(flags):
                # IDA's Wasm processor can combine multiple stack instructions
                # into one macro item. Kernel refs must use that item's head.
                source = ida_bytes.get_item_head(source)
            elif not ida_bytes.is_head(flags):
                self.diagnostics.append(dict(code='xref',offset=offset,message='reference source has no defined IDA item'))
                continue
            key_pair = (source,target)
            old = normalized.get(key_pair)
            # An IDA data xref has one type for a from/to pair. If a macro both
            # reads and writes a global, report the modifying reference as a write.
            if old is None or kind=='write':
                normalized[key_pair] = (kind,index)
        for (source,target),(kind,index) in normalized.items():
            offset = ida_loader.get_fileregion_offset(source)
            existing = list(idautils.XrefsFrom(source,0))
            if kind == 'call':
                if not any(x.to==target and x.iscode for x in existing):
                    if ida_xref.add_cref(source,target,ida_xref.fl_CN | ida_xref.XREF_USER):
                        owned.append((offset,kind,index))
            else:
                xtype = ida_xref.dr_R if kind=='read' else ida_xref.dr_W
                if not any(x.to==target and not x.iscode for x in existing):
                    if ida_xref.add_dref(source,target,xtype | ida_xref.XREF_USER):
                        owned.append((offset,kind,index))
        save_blob(self.node,'R',dict(key=key,owned=owned))
        self._digest, self._module = key, self.session.module
