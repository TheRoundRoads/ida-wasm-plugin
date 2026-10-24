"""Install this file and wasm_decompiler/ together in IDA's user plugins directory."""
import ida_idaapi


class WasmDecompilerPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = 'Independent WebAssembly decompiler for IDA 9.0+'
    help = 'Open a Wasm function and press Tab.'
    wanted_name = 'Wasm decompiler'
    wanted_hotkey = ''

    def init(self):
        from wasm_decompiler.ida_plugin import Manager
        self.manager = Manager()
        self.manager.install()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        import ida_kernwin
        try:
            session = self.manager.ensure_session()
            self.manager.open_function(session.function_at(ida_kernwin.get_screen_ea()))
        except (ValueError,OSError) as exc:
            ida_kernwin.warning('Wasm decompiler: '+str(exc))

    def term(self):
        if hasattr(self,'manager'):
            self.manager.uninstall()


def PLUGIN_ENTRY():
    return WasmDecompilerPlugin()
