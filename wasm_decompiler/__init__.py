"""Independent WebAssembly decompiler with an optional IDAPython adapter."""
from .binary import parse_module, WasmError
from .decompile import Options, Result, decompile_function, decompile_module, export_text
__version__ = '0.3.0'
