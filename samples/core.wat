(module
  (memory (export "memory") 1)
  (global $__stack_pointer (export "__stack_pointer") (mut i32) (i32.const 65536))
  (func $add (export "add") (param $a i32) (param $b i32) (result i32)
    local.get $a local.get $b i32.add)
  (func (export "factorial") (param $n i32) (result i32) (local $acc i32)
    i32.const 1 local.set $acc
    block $done
      loop $again
        local.get $n i32.eqz br_if $done
        local.get $acc local.get $n i32.mul local.set $acc
        local.get $n i32.const 1 i32.sub local.set $n
        br $again
      end
    end
    local.get $acc)
  (func (export "choose") (param i32) (result i32)
    local.get 0 if (result i32) i32.const 42 else i32.const 7 end)
  (func (export "branch_value") (param i32) (result i32)
    block (result i32) i32.const 42 local.get 0 br_if 0 drop i32.const 7 end)
  (func (export "memory_roundtrip") (param i32) (result i32)
    i32.const 0 local.get 0 i32.store
    i32.const 0 i32.load)
  (func (export "select_eager") (result i32)
    i32.const 0 i32.const 1 i32.const 0 select)
  (func (export "test_add") (result i32) i32.const 20 i32.const 22 call $add)
)
