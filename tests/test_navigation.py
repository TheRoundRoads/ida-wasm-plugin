from pathlib import Path
import pytest
from wasm_decompiler.navigation import identifier_at,symbol_at
from wasm_decompiler.references import collect_references
from wasm_decompiler import parse_module,decompile_function,WasmError

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('text,column,expected',[
    ('    _f1387(0);',4,'_f1387'),
    ('    _f1387(0);',8,'_f1387'),
    ('    _f1387(0);',10,'_f1387'),
    ('return _f1387(20,22);',10,'_f1387'),
    ('global_0=arg_0;',4,'global_0'),
    ('global_0=arg_0;',11,'arg_0'),
    ('memory+global_0+8',9,'global_0'),
    ('_name_42;',4,'_name_42'),
    ('0xdeadbeef',4,None),
    ('123foo',4,None),
    ('    ',2,None),
    ('word',-1,None),
])
def test_identifier_hit_testing(text,column,expected):
    assert identifier_at(text,column)==expected


def test_symbol_resolution_uses_exact_identifiers():
    target=dict(kind='function',index=1387)
    assert symbol_at('_f1387(0);',3,{'_f1387':target}) == ('_f1387',target)
    assert symbol_at('_f13870(0);',3,{'_f1387':target}) == (None,None)


def test_globals_and_calls_have_source_references():
    module=parse_module((ROOT/'samples/navigation.wasm').read_bytes())
    references,diagnostics=collect_references(module)
    assert not diagnostics
    assert [kind for _,kind,_ in references]==['read','write','call']
    assert references[0][2]==references[1][2]==0
    assert references[2][2]==0
    assert all(module.functions[0].code_offset <= offset < len(module.data) for offset,_,_ in references)
    result=decompile_function(module,0)
    assert result.symbols['global_0']==dict(kind='global',index=0)


def test_reference_scan_isolates_unsupported_functions():
    module=parse_module((ROOT/'samples/navigation.wasm').read_bytes())
    data=bytearray(module.data)
    data[module.functions[0].code_offset]=0xfd
    references,diagnostics=collect_references(parse_module(data))
    assert [kind for _,kind,_ in references]==['write','call']
    assert len(diagnostics)==1 and diagnostics[0]['code']=='unsupported'


def test_reference_scan_cancellation():
    module=parse_module((ROOT/'samples/navigation.wasm').read_bytes())
    with pytest.raises(WasmError,match='cancelled'):
        collect_references(module,lambda:True)
