import json
import ida_auto
import ida_funcs
import ida_loader
import ida_nalt
import ida_segment
import ida_idaapi
import ida_pro
import idautils
ida_auto.auto_wait()
report = {'input':ida_nalt.get_input_file_path(), 'segments':[], 'functions':[]}
for ea in idautils.Segments():
    s = ida_segment.getseg(ea)
    report['segments'].append([ida_segment.get_segm_name(s),s.start_ea,s.end_ea,ida_loader.get_fileregion_offset(s.start_ea)])
for ea in idautils.Functions():
    f = ida_funcs.get_func(ea)
    report['functions'].append([ea,f.end_ea,ida_funcs.get_func_name(ea),ida_loader.get_fileregion_offset(ea)])
with open('/tmp/ida-wasm-probe.json','w') as out:
    json.dump(report,out,indent=2)
ida_pro.qexit(0)
