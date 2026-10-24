"""Execute rendered IR as C for a supported helper subset and compare to WABT.

This checks the actual rendered statements, branch transfers, evaluation order,
and optimization, rather than comparing two users of the same Wasm decoder.
"""
import ctypes
import random
import re
import subprocess
import pytest

from wasm_decompiler import parse_module, decompile_module, Options, export_text

RUNTIME = r'''
#include <stdint.h>
#include <string.h>
#define __trap() __builtin_trap()
#define __rotl32 wasm_i32_rotl
#define __rotl64 wasm_i64_rotl
#define __rotr32 wasm_i32_rotr
#define __rotr64 wasm_i64_rotr
#define __i32_reinterpret_f32 wasm_i32_reinterpret_f32
#define __i64_reinterpret_f64 wasm_i64_reinterpret_f64
static uint8_t memory[65536];
static int32_t wasm_as_i32_signed(uint32_t x) { int32_t s; memcpy(&s,&x,4); return s; }
static int64_t wasm_as_i64_signed(uint64_t x) { int64_t s; memcpy(&s,&x,8); return s; }
static uint32_t wasm_i32_shl(uint32_t x,uint32_t n) { return x<<(n&31); }
static uint32_t wasm_i32_shr_u(uint32_t x,uint32_t n) { return x>>(n&31); }
static uint32_t wasm_i32_shr_s(uint32_t x,uint32_t n) { n&=31; return n ? (x>>n)|((x&0x80000000)?(~0u<<(32-n)):0) : x; }
static uint64_t wasm_i64_shl(uint64_t x,uint64_t n) { return x<<(n&63); }
static uint64_t wasm_i64_shr_u(uint64_t x,uint64_t n) { return x>>(n&63); }
static uint64_t wasm_i64_shr_s(uint64_t x,uint64_t n) { n&=63; return n ? (x>>n)|((x>>63)?(~0ull<<(64-n)):0) : x; }
static uint32_t wasm_i32_rotl(uint32_t x,uint32_t n) { n&=31; return n?(x<<n)|(x>>(32-n)):x; }
static uint64_t wasm_i64_rotl(uint64_t x,uint64_t n) { n&=63; return n?(x<<n)|(x>>(64-n)):x; }
static uint32_t wasm_i32_rotr(uint32_t x,uint32_t n) { n&=31; return n?(x>>n)|(x<<(32-n)):x; }
static uint64_t wasm_i64_rotr(uint64_t x,uint64_t n) { n&=63; return n?(x>>n)|(x<<(64-n)):x; }
static uint32_t wasm_i32_div_u(uint32_t x,uint32_t y) { return x/y; }
static uint64_t wasm_i64_div_u(uint64_t x,uint64_t y) { return x/y; }
static uint32_t wasm_i32_rem_u(uint32_t x,uint32_t y) { return x%y; }
static uint64_t wasm_i64_rem_u(uint64_t x,uint64_t y) { return x%y; }
static float wasm_f32_from_bits(uint32_t x) { float f; memcpy(&f,&x,4); return f; }
static double wasm_f64_from_bits(uint64_t x) { double f; memcpy(&f,&x,8); return f; }
static uint32_t wasm_i32_reinterpret_f32(float x) { uint32_t n; memcpy(&n,&x,4); return n; }
static uint64_t wasm_i64_reinterpret_f64(double x) { uint64_t n; memcpy(&n,&x,8); return n; }
static float wasm_f32_add(float x,float y) { return x+y; }
static double wasm_f64_add(double x,double y) { return x+y; }
static void wasm_i32_store(uint32_t address,uint32_t offset,uint32_t value) { memcpy(memory+(uint64_t)address+offset,&value,4); }
static uint32_t wasm_i32_load(uint32_t address,uint32_t offset) { uint32_t v; memcpy(&v,memory+(uint64_t)address+offset,4); return v; }
static uint32_t wasm_i32_wrap_i64(uint64_t x) { return (uint32_t)x; }
'''


def execute_comparison(wat, tmp_path, optimize, c_style=False):
    source, binary = tmp_path/'test.wat',tmp_path/'test.wasm'
    source.write_text(wat)
    subprocess.run(['wat2wasm',str(source),'-o',str(binary),'--debug-names'],check=True,capture_output=True)
    expected = subprocess.run(['wasm-interp',str(binary),'--run-all-exports'],check=True,capture_output=True,text=True).stdout
    module = parse_module(binary.read_bytes())
    results = decompile_module(module,Options(optimize=optimize,c_style=c_style))
    assert all(r.success for r in results)
    cfile,library = tmp_path/'generated.c',tmp_path/'generated.so'
    cfile.write_text(RUNTIME+'\n'+export_text(module,results))
    subprocess.run(['cc','-std=c11','-O2','-shared','-fPIC',str(cfile),'-o',str(library)],check=True,capture_output=True)
    lib = ctypes.CDLL(str(library))
    count = 0
    for name,kind,value in re.findall(r'^(\w+)\(\) => (i32|i64):(\d+)$',expected,re.M):
        fn = getattr(lib,name)
        fn.argtypes = []
        fn.restype = ctypes.c_uint32 if kind == 'i32' else ctypes.c_uint64
        assert fn() == int(value),(name,kind,value)
        count += 1
    assert count > 0,expected
    return count


@pytest.mark.parametrize('optimize',[False,True])
@pytest.mark.parametrize('c_style',[False,True])
def test_random_numeric_execution(tmp_path,optimize,c_style):
    rng = random.Random(20261024)
    functions = []
    for t,bits in [('i32',32),('i64',64)]:
        for op in ('add','sub','mul','and','or','xor','shl','shr_s','shr_u','rotl','rotr','div_u','rem_u','eq','ne','lt_s','lt_u','le_s','ge_u','gt_s'):
            for k in range(4):
                a,b = rng.getrandbits(bits),rng.getrandbits(bits) or 1
                result_type = 'i32' if op.split('_')[0] in ('eq','ne','lt','le','ge','gt') else t
                functions.append(f'(func (export "test_{t}_{op}_{k}") (result {result_type}) {t}.const {a} {t}.const {b} {t}.{op})')
    # Float helpers must preserve bit patterns, including negative zero.
    for t,itype in [('f32','i32'),('f64','i64')]:
        for k,(a,b) in enumerate([('1.5','2.25'),('-0','-0'),('1e10','-1e10')]):
            functions.append(f'(func (export "test_{t}_{k}") (result {itype}) {t}.const {a} {t}.const {b} {t}.add {itype}.reinterpret_{t})')
    assert execute_comparison('(module '+''.join(functions)+')',tmp_path,optimize,c_style) == 166


@pytest.mark.parametrize('optimize',[False,True])
@pytest.mark.parametrize('c_style',[False,True])
def test_control_flow_execution(tmp_path,optimize,c_style):
    wat = '''(module (memory 1) (global (mut i32) (i32.const 0))
      (func $fact (param $n i32) (result i32) (local $acc i32)
        i32.const 1 local.set $acc
        block $done loop $again
          local.get $n i32.eqz br_if $done
          local.get $acc local.get $n i32.mul local.set $acc
          local.get $n i32.const 1 i32.sub local.set $n br $again
        end end local.get $acc)
      (func $switcher (param i32) (result i32)
        block $out (result i32)
          block $case1 block $case0
            local.get 0 br_table $case0 $case1 $out
          end i32.const 11 br $out
          end i32.const 22
        end)
      (func $choose (param i32) (result i32)
        block (result i32) i32.const 42 local.get 0 br_if 0 drop i32.const 7 end)
      (func $rootbranch (param i32) (result i32)
        i32.const 99 local.get 0 br_if 0 drop i32.const 7)
      (func $nested (param i32) (result i32)
        local.get 0 if (result i32)
          i32.const 17
        else
          i32.const 0 if (result i32) i32.const 23 else i32.const 31 end
        end)
      (func $effect (result i32)
        global.get 0 i32.const 1 i32.add global.set 0 global.get 0)
      (func (export "test_eager") (result i32)
        call $effect call $effect i32.const 1 select)
      (func (export "test_memory") (result i32)
        i32.const 0 i32.const 12345 i32.store i32.const 0 i32.load)
      (func (export "test_snapshot") (result i32) (local i32)
        i32.const 7 local.set 0 local.get 0 i32.const 9 local.set 0 local.get 0 i32.add)
      (func (export "test_transfer") (result i32)
        block (result i32) i32.const 11 i64.const 99 i32.const 42 br 0 end)
      (func (export "test_root_return") (result i32)
        block i64.const 999 drop i32.const 42 br 1 end unreachable)
      (func (export "test_dead") (result i32)
        i32.const 42 return unreachable block i64.const 99 drop end unreachable)
      (func (export "test_same_slot_different_type") (result i32)
        i64.const 4294967338 i32.wrap_i64)
      WRAPPERS
    )'''
    # switcher default label carries an i32 result and needs a value before selector.
    wat = wat.replace('local.get 0 br_table $case0 $case1 $out','local.get 0 br_table $case0 $case1 $case1')
    wrappers = []
    for fn in ('fact','switcher','choose','rootbranch','nested'):
        for k in range(7):
            wrappers.append(f'(func (export "test_{fn}_{k}") (result i32) i32.const {k} call ${fn})')
    assert execute_comparison(wat.replace('WRAPPERS',''.join(wrappers)),tmp_path,optimize,c_style) == 42

STACK_RUNTIME = r'''
typedef struct { uint32_t address, offset; } wasm_stack_slot_i32;
static wasm_stack_slot_i32 wasm_stack_bind_i32(uint32_t a,uint32_t o) { return (wasm_stack_slot_i32){a,o}; }
static void wasm_stack_store_i32(wasm_stack_slot_i32 s,uint32_t v) { wasm_i32_store(s.address,s.offset,v); }
static uint32_t wasm_stack_load_i32(wasm_stack_slot_i32 s) { return wasm_i32_load(s.address,s.offset); }
'''


@pytest.mark.parametrize('optimize',[False,True])
@pytest.mark.parametrize('c_style',[False,True])
def test_stack_recovery_execution(tmp_path,optimize,c_style):
    wat = '''(module (memory 1) (global (mut i32) (i32.const 0))
      (func (export "test_stack") (result i32) (local $frame i32) (local $result i32)
        global.get 0 i32.const 16 i32.sub local.tee $frame global.set 0
        local.get $frame i32.const 42 i32.store offset=4
        local.get $frame i32.load offset=4 local.set $result
        local.get $frame i32.const 16 i32.add global.set 0
        local.get $result))'''
    # Start at 1024 so both runtimes have a valid frame without external setup.
    wat = wat.replace('(i32.const 0))','(i32.const 1024))')
    source,binary = tmp_path/'frame.wat',tmp_path/'frame.wasm'
    source.write_text(wat)
    subprocess.run(['wat2wasm',str(source),'-o',str(binary),'--debug-names'],check=True)
    expected = subprocess.run(['wasm-interp',str(binary),'--run-all-exports'],check=True,capture_output=True,text=True).stdout
    module = parse_module(binary.read_bytes())
    results = decompile_module(module,Options(optimize=optimize,c_style=c_style))
    assert ('*stack_local_0' if c_style else 'wasm_stack_load_i32(stack_local_0)') in results[0].text
    cfile,library = tmp_path/'frame.c',tmp_path/'frame.so'
    cfile.write_text(RUNTIME+STACK_RUNTIME+export_text(module,results))
    subprocess.run(['cc','-std=c11','-O2','-shared','-fPIC',str(cfile),'-o',str(library)],check=True,capture_output=True)
    lib = ctypes.CDLL(str(library))
    ctypes.c_uint32.in_dll(lib,'global_0').value = 1024
    assert lib.test_stack() == int(re.search(r'i32:(\d+)',expected)[1]) == 42
    assert ctypes.c_uint32.in_dll(lib,'global_0').value == 1024


@pytest.mark.parametrize('c_style',[False,True])
def test_effectful_expression_order(tmp_path,c_style):
    wat = """(module (global (mut i32) (i32.const 1))
      (func $change (result i32) i32.const 2 global.set 0 i32.const 3)
      (func $peek_state (result i32) global.get 0)
      (func (export "test_global_snapshot") (result i32) global.get 0 call $change i32.add)
      (func (export "test_calls_in_order") (result i32) call $peek_state call $change i32.sub)
      (func (export "test_dropped_call") (result i32) call $change drop global.get 0))"""
    # Export harness initializes globals to zero; initialize in each exported function
    # to isolate invocation state and match the Wasm instance.
    wat = wat.replace('(result i32) global.get 0 call $change', '(result i32) i32.const 1 global.set 0 global.get 0 call $change')
    wat = wat.replace('(result i32) call $peek_state', '(result i32) i32.const 1 global.set 0 call $peek_state')
    assert execute_comparison(wat,tmp_path,True,c_style) == 3


@pytest.mark.parametrize('c_style',[False,True])
def test_nested_loop_backedges_recheck_guards(tmp_path,c_style):
    wat = '''(module
      (func $nested (param $i i32) (result i32) (local $j i32) (local $acc i32)
        block $done loop $outer
          local.get $i i32.eqz br_if $done
          i32.const 3 local.set $j
          block $inner_done loop $inner
            local.get $j i32.eqz br_if $inner_done
            local.get $acc local.get $i i32.add local.set $acc
            local.get $j i32.const 1 i32.sub local.set $j
            local.get $j i32.const 1 i32.eq if
              local.get $i i32.const 1 i32.sub local.set $i
              br $outer
            end
            br $inner
          end end
          local.get $i i32.const 1 i32.sub local.set $i
          br $outer
        end end local.get $acc)
      (func $loop_value (param $n i32) (result i32)
        loop (result i32)
          local.get $n i32.const 1 i32.sub local.tee $n
          local.get $n br_if 0
          i32.const 42 i32.add
        end)
      WRAPPERS)'''
    wrappers = ''.join(f'(func (export "test_nested_{i}") (result i32) i32.const {i} call $nested)' for i in range(7))
    wrappers += ''.join(f'(func (export "test_loop_value_{i}") (result i32) i32.const {i} call $loop_value)' for i in range(1,6))
    assert execute_comparison(wat.replace('WRAPPERS',wrappers),tmp_path,True,c_style) == 12
