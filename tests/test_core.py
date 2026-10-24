import json
from pathlib import Path
import subprocess
import pytest

from wasm_decompiler import parse_module, decompile_function, decompile_module, Options, WasmError, export_text
from wasm_decompiler.binary import Reader, NUMERIC, SAT, MEMORY, decode
from wasm_decompiler.analysis import analyze, numeric_signature

ROOT = Path(__file__).resolve().parents[1]


def compile_wat(text, tmp_path, validate=True):
    wat, wasm = tmp_path/'test.wat', tmp_path/'test.wasm'
    wat.write_text(text)
    args = ['wat2wasm',str(wat),'-o',str(wasm),'--debug-names']
    if not validate:
        args.append('--no-check')
    subprocess.run(args,check=True,capture_output=True)
    return parse_module(wasm.read_bytes())


def test_core_sample():
    m = parse_module((ROOT/'samples/core.wasm').read_bytes())
    results = decompile_module(m)
    assert all(r.success for r in results)
    assert 'return a + b;' in results[0].text
    assert 'while (n)' in results[1].text
    assert 'goto ' not in results[1].text
    assert '} else {' in results[2].text
    for f,r in zip(m.functions,results):
        for offsets in r.source_map.values():
            assert all(f.code_offset <= x < f.code_offset+len(f.code) for x in offsets)


@pytest.mark.parametrize('data', [b'\x80'*5, b'\xff\xff\xff\xff\x10', b'\x80'])
def test_invalid_unsigned_leb(data):
    with pytest.raises(WasmError):
        Reader(data).u()


@pytest.mark.parametrize('data', [b'\x80\x80\x80\x80\x08', b'\xff\xff\xff\xff\x77', b'\xff'*5])
def test_invalid_signed_leb(data):
    with pytest.raises(WasmError):
        Reader(data).leb(32,True)


def test_valid_nonminimal_leb():
    assert Reader(b'\xff\xff\xff\xff\x7f').leb(32,True) == -1
    assert Reader(b'\x80\x00').u() == 0


@pytest.mark.parametrize('name',NUMERIC + SAT)
def test_numeric_families(name,tmp_path):
    inputs,outputs = numeric_signature(name)
    args = ' '.join(f'{t}.const 1' for t in inputs)
    m = compile_wat(f'(module (func (result {outputs[0]}) {args} {name}))',tmp_path)
    result = decompile_function(m,0)
    assert result.success, result.diagnostics
    assert any(i.name == name for i in decode(m.functions[0]))


@pytest.mark.parametrize('name',MEMORY)
def test_memory_families(name,tmp_path):
    t = name[:3]
    store = '.store' in name
    body = f'i32.const 0 {t+".const 1" if store else ""} {name}'
    m = compile_wat(f'(module (memory 1) (func {"" if store else "(result "+t+")"} {body}))',tmp_path)
    assert decompile_function(m,0).success


@pytest.mark.parametrize('body',[
    'i32.add',
    'f32.const 1 i32.eqz drop',
    'i32.const 1',
    'br 1',
    'i32.const 1 if (result i32) i32.const 2 end drop',
    'i32.const 0 i32.load drop',
    'i32.const 0 local.get 99 drop drop',
])
def test_invalid_types_indices(body,tmp_path):
    m = compile_wat(f'(module (func {body}))',tmp_path,validate=False)
    r = decompile_function(m,0)
    assert not r.success
    assert r.diagnostics[0]['code'] == 'invalid'


def test_unknown_opcode_isolated(tmp_path):
    m = compile_wat('(module (func nop) (func nop))',tmp_path)
    data = bytearray(m.data)
    data[m.functions[0].code_offset] = 0xfd
    m = parse_module(data)
    results = decompile_module(m)
    assert not results[0].success
    assert results[0].diagnostics[0]['code'] == 'unsupported'
    assert results[1].success


def test_multi_value_rejected(tmp_path):
    with pytest.raises(WasmError,match='multi-value'):
        compile_wat('(module (func (result i32 i32) i32.const 1 i32.const 2))',tmp_path)


def test_branch_stack_moves(tmp_path):
    m = compile_wat('''(module (func (result i32)
      block (result i32) i32.const 11 i64.const 99 i32.const 42 br 0 end))''',tmp_path)
    text = decompile_function(m,0,Options(optimize=False,c_style=False)).text
    assert 'v0_i32 = v2_i32;' in text


def test_br_table_and_function_branch(tmp_path):
    m = compile_wat('''(module (func (param i32) (result i32)
      block (result i32) i32.const 5 local.get 0 br_table 0 1 end))''',tmp_path)
    r = decompile_function(m,0)
    assert r.success
    assert 'switch (' in r.text and 'return tmp1;' in r.text


def test_unreachable_polymorphism(tmp_path):
    m = compile_wat('''(module (func (result i64)
      unreachable i32.add drop block i64.const 3 drop end))''',tmp_path)
    r = decompile_function(m,0)
    assert r.success
    assert '__trap()' in r.text
    assert 'wasm_i32_add' not in r.text


def test_bulk_memory(tmp_path):
    m = compile_wat('''(module (memory 1) (table 1 funcref)
      (data "hello") (elem func 0)
      (func
        i32.const 0 i32.const 0 i32.const 5 memory.init 0 data.drop 0
        i32.const 0 i32.const 0 i32.const 1 memory.copy
        i32.const 0 i32.const 42 i32.const 5 memory.fill
        i32.const 0 i32.const 0 i32.const 1 table.init 0 elem.drop 0
        i32.const 0 i32.const 0 i32.const 1 table.copy))''',tmp_path)
    result = decompile_function(m,0)
    assert result.success, result.diagnostics
    for op in ('__memory_init','memmove','memset','__table_init','__table_copy','__data_drop','__elem_drop'):
        assert op in result.text


def test_select_effects_stay_eager(tmp_path):
    m = compile_wat('''(module (memory 1) (func (result i32)
       i32.const 65536 i32.load i32.const 0 i32.const 0 select))''',tmp_path)
    r = decompile_function(m,0)
    assert r.success
    assert r.text.index('*(uint32_t *)') < r.text.index(' ? ')


def test_call_local_snapshot(tmp_path):
    m = compile_wat('''(module (import "env" "side_effect" (func $f (result i32)))
      (func (param i32) (result i32) local.get 0 call $f i32.const 2 local.set 0 i32.add))''',tmp_path)
    r = decompile_function(m,1)
    assert r.success
    assert 'arg_0 = 2' not in r.text  # dead local write is removed
    assert 'f()' in r.text and 'arg_0' in r.text


def test_cancel():
    m = parse_module((ROOT/'samples/core.wasm').read_bytes())
    assert decompile_function(m,0,cancelled=lambda:True).diagnostics[0]['code'] == 'cancelled'


def test_duplicate_names_and_reserved(tmp_path):
    m = compile_wat('(module (func $if) (func $wasm_trap))',tmp_path)
    assert decompile_function(m,0).name != 'if'
    assert decompile_function(m,1).name != 'wasm_trap'


def test_cli(tmp_path):
    output = tmp_path/'result.json'
    p = subprocess.run(['/usr/bin/python3','-m','wasm_decompiler',str(ROOT/'samples/core.wasm'),'--json','-o',str(output)],cwd=ROOT,capture_output=True)
    assert p.returncode == 0,p.stderr
    assert len(json.loads(output.read_text())['results']) == 7


def test_truncated_sections():
    data = (ROOT/'samples/core.wasm').read_bytes()
    for end in (0,7,9,12,len(data)-1):
        with pytest.raises(WasmError):
            parse_module(data[:end])


def test_public_corpus():
    for path in (ROOT/'samples/public').glob('*.wasm'):
        m = parse_module(path.read_bytes())
        assert all(r.success for r in decompile_module(m)),path


def test_private_table_resolution(tmp_path):
    m = compile_wat('''(module (type (func (result i32))) (table 1 funcref)
      (elem (i32.const 0) $target)
      (func $target (result i32) i32.const 42)
      (func (result i32) i32.const 0 call_indirect (type 0)))''',tmp_path)
    r = decompile_function(m,1)
    assert r.success
    assert 'target()' in r.text
    assert 'wasm_call_indirect' not in r.text


def test_exported_table_not_resolved(tmp_path):
    m = compile_wat('''(module (type (func (result i32))) (table (export "table") 1 funcref)
      (elem (i32.const 0) $target)
      (func $target (result i32) i32.const 42)
      (func (result i32) i32.const 0 call_indirect (type 0)))''',tmp_path)
    assert '__indirect_call' in decompile_function(m,1).text


def test_stack_recovery(tmp_path):
    m = compile_wat('''(module (memory 1)
      (global (mut i32) (i32.const 65536))
      (func (result i32) (local $frame i32) (local $answer i32)
        global.get 0 i32.const 16 i32.sub local.tee $frame global.set 0
        local.get $frame i32.const 42 i32.store offset=4
        local.get $frame i32.load offset=4 local.set $answer
        local.get $frame i32.const 16 i32.add global.set 0
        local.get $answer))''',tmp_path)
    r = decompile_function(m,0)
    assert r.success,r.diagnostics
    assert 'uint32_t * stack_local_0;' in r.text
    assert '*stack_local_0 = 42;' in r.text
    assert '= *stack_local_0;' in r.text
    assert 'wasm_stack_' not in decompile_function(m,0,Options(recover_stack=False)).text


def test_stack_override_errors():
    m = parse_module((ROOT/'samples/core.wasm').read_bytes())
    assert not decompile_function(m,0,Options(stack_pointer=99)).success


def test_stack_frame_escapes(tmp_path):
    m = compile_wat('''(module (memory 1) (global (mut i32) (i32.const 65536))
      (func (result i32) (local i32)
        global.get 0 i32.const 16 i32.sub local.tee 0 global.set 0
        local.get 0 i32.const 42 i32.store
        local.get 0 i32.const 16 i32.add global.set 0
        local.get 0))''',tmp_path)
    assert 'wasm_stack_slot' not in decompile_function(m,0).text


def test_table_index_global_changed_by_call(tmp_path):
    m = compile_wat('''(module (type (func (result i32)))
      (import "host" "change_global" (func $change))
      (global (export "index") (mut i32) (i32.const 0))
      (table 1 funcref) (elem (i32.const 0) $target)
      (func $target (result i32) i32.const 42)
      (func (result i32)
        i32.const 0 global.set 0 call $change
        global.get 0 call_indirect (type 0)))''',tmp_path)
    r = decompile_function(m,2)
    assert r.success
    assert '__indirect_call' in r.text


def test_long_expression_has_bounded_depth(tmp_path):
    m = compile_wat('(module (func (result i32) i32.const 0 '+'i32.const 1 i32.add '*2000+'))',tmp_path)
    r = decompile_function(m,0)
    assert r.success
    assert max((s.expr.depth for s in r.statements if s.expr),default=0) <= 64


def test_public_manifest_hashes():
    import hashlib
    manifest = json.loads((ROOT/'samples/public/manifest.json').read_text())
    assert len(manifest['files']) == 7
    for item in manifest['files']:
        assert hashlib.sha256((ROOT/'samples/public'/item['path']).read_bytes()).hexdigest() == item['sha256']


def test_distribution_layout(tmp_path):
    from tools.package_plugin import build
    import zipfile
    with zipfile.ZipFile(build(tmp_path/'plugin.zip')) as archive:
        names = archive.namelist()
        assert [name for name in names if '/' not in name] == ['ida_wasm_decompiler.py']
        assert all(name == 'ida_wasm_decompiler.py' or name.startswith('wasm_decompiler/') for name in names)
        for name in ('LICENSE','THIRD_PARTY.md','README.md','docs/HELPERS.md'):
            assert 'wasm_decompiler/'+name in names
        assert archive.testzip() is None
