(module
  (global $state (mut i32) (i32.const 4096))
  (func $callee (param $value i32) (result i32)
    global.get $state local.get $value i32.add)
  (func $run (export "run") (param $value i32) (result i32)
    local.get $value global.set $state
    local.get $value call $callee))
