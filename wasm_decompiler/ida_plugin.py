"""IDA 9.0+ adapter. Imported only inside IDA; core remains standalone."""
import hashlib
import json
from pathlib import Path
import re
import zlib
from dataclasses import replace

import ida_bytes
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin as ui
import ida_lines
import ida_loader
import ida_name
import ida_nalt
import ida_netnode
import ida_segment

from . import parse_module, WasmError, Options, decompile_function, export_text
from .navigation import identifier_at, symbol_at
from .ida_database import DatabaseSymbols


class Session:
    def __init__(self):
        self.node = ida_netnode.netnode('$ ida-wasm-decompiler', 0, True)
        saved = self.node.getblob(0, 'S')
        self.settings = json.loads(saved.decode('utf-8')) if saved else {'locals':{}, 'stack_pointer':None}
        cached = self.node.getblob(0, 'M')
        if cached:
            self.original = zlib.decompress(cached)
        else:
            path = ida_nalt.get_input_file_path()
            if not Path(path).is_file():
                path = ui.ask_file(False, '*.wasm', 'Locate the original WebAssembly module')
            if not path:
                raise WasmError('original input is required to read module metadata')
            self.original = Path(path).read_bytes()
            digest = ida_nalt.retrieve_input_file_sha256()
            if digest and hashlib.sha256(self.original).digest() != bytes(digest):
                raise WasmError('selected file does not match the database input SHA-256')
            parse_module(self.original)
            self.node.setblob(zlib.compress(self.original), 0, 'M')
        self.base = parse_module(self.original)
        self.module, self.cache, self.dirty = self.base, {}, True
        self._names, self._global_names, self.names_version = None, None, 0
        self.update()
        self.symbols = DatabaseSymbols(self)

    def save(self):
        self.node.setblob(json.dumps(self.settings).encode('utf-8'), 0, 'S')

    def ea(self, offset):
        return ida_loader.get_fileregion_ea(offset)

    def update(self):
        if not self.dirty:
            return
        data = bytearray(self.original)
        ea = ida_segment.get_first_seg()
        while ea:
            segment = ea
            off = ida_loader.get_fileregion_offset(segment.start_ea)
            count = min(segment.end_ea-segment.start_ea, len(data)-off) if off >= 0 else 0
            if count > 0:
                last = ida_loader.get_fileregion_offset(segment.start_ea+count-1)
                if last != off+count-1:
                    raise WasmError('non-contiguous file mapping; cannot safely overlay database bytes', off)
                content = ida_bytes.get_bytes(segment.start_ea, count)
                if content is None:
                    raise WasmError('could not read mapped database bytes', off)
                data[off:off+count] = content
            ea = ida_segment.get_next_seg(segment.start_ea)
        # Only instruction-byte patches are supported. Module structure is stable.
        ranges = sorted((f.code_offset, f.code_offset+len(f.code)) for f in self.base.functions if not f.imported)
        cursor = 0
        for start,end in ranges + [(len(data),len(data))]:
            if data[cursor:start] != self.original[cursor:start]:
                raise WasmError('patched module metadata or locals: reload a rebuilt Wasm file', cursor)
            cursor = end
        self.module = parse_module(bytes(data))
        self.dirty = False

    def names(self):
        if self._names is not None:
            return self._names
        names = {}
        for f in self.module.functions:
            if not f.imported:
                ea = self.ea(f.code_offset)
                name = ida_name.get_name(ea) if ea != ida_idaapi.BADADDR else ''
                if name:
                    names[f.index] = name
        self._names = names
        return names

    def global_names(self):
        if self._global_names is None:
            used = set(self.names().values())
            used.update(name for function in self.module.functions for name in function.local_names.values())
            used.update(name for values in self.settings['locals'].values() for name in values.values())
            names = {}
            for i in range(len(self.module.globals)):
                name = ida_name.get_name(self.symbols.global_ea(i)) or f'global_{i}'
                name = re.sub(r'[^a-zA-Z0-9_]', '_',name)
                if not name or name[0].isdigit():
                    name = 'global_'+name
                base,suffix = name,1
                while name in used or re.fullmatch(r'(?:arg_|local_|tmp|stack_local_)\d+',name):
                    name,suffix = f'{base}_global{suffix}',suffix+1
                names[i] = name
                used.add(name)
            self._global_names = names
        return self._global_names

    def function_at(self, ea):
        off = ida_loader.get_fileregion_offset(ea)
        for f in self.module.functions:
            if not f.imported and f.code_offset <= off < f.code_offset+len(f.code):
                return f.index
        raise WasmError('cursor is not inside a mapped Wasm function')

    def result(self, index):
        self.update()
        self.symbols.ensure_index(ui.user_cancelled)
        names = self.names()
        options = Options(stack_pointer=self.settings.get('stack_pointer'))
        local_names = {int(k):v for k,v in self.settings['locals'].get(str(index),{}).items()}
        key = (index, self.names_version, json.dumps(local_names,sort_keys=True), options.stack_pointer)
        if key not in self.cache:
            result = decompile_function(self.module,index,options,names,local_names,ui.user_cancelled)
            if any(d['code'] == 'cancelled' for d in result.diagnostics):
                return result
            global_names = self.global_names()
            replacements = {f'global_{i}':name for i,name in global_names.items()}
            text = re.sub(r'\bglobal_\d+\b',lambda m:replacements.get(m[0],m[0]),result.text)
            symbols = {}
            for name,symbol in result.symbols.items():
                symbol = dict(symbol)
                if symbol['kind'] == 'global':
                    name = global_names[symbol['index']]
                    symbol['ea'] = self.symbols.global_ea(symbol['index'])
                elif symbol['kind'] == 'function':
                    symbol['ea'] = self.symbols.function_ea(symbol['index'])
                symbols[name] = symbol
            self.cache[key] = replace(result,text=text,symbols=symbols)
        return self.cache[key]

    def invalidate_names(self):
        self._names, self._global_names = None, None
        self.names_version += 1
        self.cache.clear()

    def invalidate(self):
        self.dirty = True
        self.invalidate_names()


KEYWORDS = re.compile(r'\b(if|else|do|while|switch|case|default|goto|return|uint8_t|uint16_t|uint32_t|uint64_t|int8_t|int16_t|int32_t|int64_t|float|double|void|break|continue)\b')


def colorize(line):
    def token(match):
        word = match[0]
        if word.startswith(('//','/*')):
            color = ida_lines.SCOLOR_AUTOCMT
        elif KEYWORDS.fullmatch(word):
            color = ida_lines.SCOLOR_KEYWORD
        elif word[0].isdigit():
            color = ida_lines.SCOLOR_NUMBER
        elif line[match.end():].lstrip().startswith('('):
            color = ida_lines.SCOLOR_CNAME
        else:
            return word
        return ida_lines.COLSTR(word,color)
    return re.sub(r'//.*|/\*.*?\*/|\b(?:0x[0-9a-fA-F]+|[0-9]+)(?:ULL|ull|[uf])?\b|\b[A-Za-z_][A-Za-z_0-9]*\b',token,line)


class Viewer(ui.simplecustviewer_t):
    def __init__(self, manager, index):
        super().__init__()
        self.manager, self.index, self.result = manager,index,None
        self.line_map = {}
        self.history, self.future = [], []

    def navigate(self, index, record=True, position=None):
        previous = self.index
        if index != previous and record:
            self.history.append((previous,self.GetPos()))
            self.future.clear()
        self.manager.views.pop(previous,None)
        self.index = index
        self.manager.views[index] = self
        self.refresh_result()
        if position:
            self.Jump(*position)
        else:
            self.Jump(0)

    def back(self, forward=False):
        source,destination = (self.future,self.history) if forward else (self.history,self.future)
        if not source:
            return False
        destination.append((self.index,self.GetPos()))
        index,position = source.pop()
        self.navigate(index,record=False,position=position)
        return True

    def resolve_symbol(self, mouse=False):
        symbols = dict(self.result.symbols)
        symbols[self.result.name] = dict(kind='function',index=self.index,
                                         ea=self.manager.session.symbols.function_ea(self.index))
        # GetCurrentWord() is whitespace based, not a C identifier tokenizer.
        # Use the actual plain-text line and mouse/cursor column instead.
        positions = [True,False] if mouse else [False]
        for from_mouse in positions:
            position = self.GetPos(1 if from_mouse else 0)
            if not position:
                continue
            row = self.GetLine(position[0])
            if not row:
                continue
            name,symbol = symbol_at(ida_lines.tag_remove(row[0]),position[1],symbols)
            if symbol:
                return name,symbol
            if from_mouse:
                # A real click on whitespace must not follow an unrelated cursor.
                return None,None
        return None,None

    def follow(self, mouse=False):
        name,symbol = self.resolve_symbol(mouse)
        if symbol and symbol['kind'] == 'function':
            position = self.GetPos()
            offsets = self.line_map.get(position[0],[]) if position else []
            if offsets:
                self.manager.disassembly_ea = self.manager.session.ea(offsets[0])
            self.manager.open_function(symbol['index'])
        elif symbol and symbol['kind'] == 'global':
            self.manager.show_disassembly(symbol['ea'])
        elif symbol and symbol['kind'] == 'local':
            uses = self.local_uses(name)
            if uses:
                self.Jump(uses[0][0])
        # Never silently jump to the caller when symbol lookup fails.

    def goto_address(self):
        default = self.manager.current_ea(self)
        address = ui.ask_addr(default,'Jump to address or symbol')
        if address is not None and address != ida_idaapi.BADADDR:
            self.manager.navigate_address(address)

    def local_uses(self,name):
        uses = []
        for i in range(self.Count()):
            line = ida_lines.tag_remove(self.GetLine(i)[0])
            if re.search(r'\b'+re.escape(name)+r'\b',line):
                uses.append((i,line.strip()))
        return uses

    def xrefs(self):
        name,symbol = self.resolve_symbol()
        if not symbol:
            ui.msg('Wasm decompiler: place the cursor on a function, global or local variable.\n')
            return
        if symbol['kind'] == 'local':
            uses = self.local_uses(name)
            class Uses(ui.Choose):
                def __init__(self):
                    super().__init__('Uses of '+name,[['Line',8],['Pseudocode',80]])
                def OnGetSize(self):
                    return len(uses)
                def OnGetLine(self,index):
                    return [str(uses[index][0]+1),uses[index][1]]
            selected = Uses().Show(True)
            if selected is not None and 0 <= selected < len(uses):
                self.Jump(uses[selected][0])
            return
        target = symbol.get('ea',ida_idaapi.BADADDR)
        if target == ida_idaapi.BADADDR:
            ui.msg('Wasm decompiler: this symbol has no mapped database address.\n')
            return
        source = ui.choose_xref(target)
        if source is not None and source != ida_idaapi.BADADDR:
            self.manager.navigate_address(source)

    def create(self):
        if not self.Create('Wasm pseudocode'):
            return False
        self.refresh_result()
        return True

    def refresh_result(self):
        ui.show_wait_box('Decompiling WebAssembly; Cancel stops analysis')
        try:
            self.result = self.manager.session.result(self.index)
            self.ClearLines()
            diagnostics = [f'// {d["code"]}: {d["message"]} (0x{d["offset"]:x})' for d in self.result.diagnostics]
            lines = ['// Tab: disassembly  Enter/double-click: follow  G: go to  X: xrefs  Esc: back'] + diagnostics
            self.line_map = {len(lines)+line-1:offsets for line,offsets in self.result.source_map.items()}
            for line in lines + self.result.text.splitlines():
                self.AddLine(colorize(line))
            self.Refresh()
        finally:
            ui.hide_wait_box()

    def jump(self):
        pos = self.GetPos()
        offsets = self.line_map.get(pos[0],[]) if pos else []
        if offsets:
            ea = self.manager.session.ea(offsets[0])
            if ea != ida_idaapi.BADADDR:
                ui.jumpto(ea)

    def rename(self):
        word,symbol = self.resolve_symbol()
        if not symbol:
            return
        name = ui.ask_str(word,0,'New identifier')
        if not name:
            return
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',name):
            ui.warning('Use a C identifier containing letters, digits, and underscores.')
            return
        session = self.manager.session
        if symbol['kind'] == 'function':
            f = session.module.functions[symbol['index']]
            if f.imported:
                ui.warning('Imported function names come from the module.')
                return
            if not ida_name.set_name(session.ea(f.code_offset),name,ida_name.SN_CHECK):
                return
        elif symbol['kind'] == 'global':
            if not ida_name.set_name(symbol['ea'],name,ida_name.SN_CHECK):
                return
        else:
            session.settings['locals'].setdefault(str(self.index),{})[str(symbol['index'])] = name
            session.save()
        session.invalidate_names()
        self.refresh_result()

    def OnDblClick(self, shift):
        try:
            self.follow(mouse=True)
        except (WasmError,OSError) as exc:
            ui.warning(str(exc))
        return True

    def OnKeydown(self, key, shift):
        try:
            if key == 9:
                self.manager.toggle(self.GetWidget())
            elif key == 13:
                self.follow()
            elif key == 37 and shift & ui.VES_ALT:
                self.back()
            elif key == 39 and shift & ui.VES_ALT:
                self.back(forward=True)
            elif key == ord('R'):
                self.manager.session.invalidate()
                self.refresh_result()
            elif key == ord('G'):
                self.goto_address()
            elif key == ord('J'):
                self.jump()
            elif key == ord('X'):
                self.xrefs()
            elif key == ord('N'):
                self.rename()
            elif key == ord('E'):
                self.manager.export(self)
            elif key == 27:
                if not self.back():
                    self.manager.toggle(self.GetWidget())
            else:
                return False
        except (WasmError,OSError) as exc:
            ui.warning(str(exc))
        return True

    def OnPopup(self, widget, popup):
        for action in ('decompile','back','forward','refresh','goto','xrefs','jump','rename','export','export_module','stack_pointer'):
            ui.attach_action_to_popup(widget,popup,'wasm_decompiler:'+action)

    def OnClose(self):
        self.manager.views.pop(self.index,None)
        if self.manager.viewer is self:
            self.manager.viewer = None


class Handler(ui.action_handler_t):
    def __init__(self, manager, action):
        super().__init__()
        self.manager, self.action = manager,action

    def activate(self, ctx):
        try:
            self.manager.dispatch(self.action,ctx)
        except (WasmError,OSError,ValueError) as exc:
            ui.warning('Wasm decompiler: '+str(exc))
        return 1

    def update(self, ctx):
        if ida_ida.inf_get_procname() != 'wasm':
            return ui.AST_DISABLE_FOR_WIDGET
        if self.action == 'decompile':
            widget = getattr(ctx,'widget',None)
            if not self.manager.owns(widget) and (not widget or ui.get_widget_type(widget) != ui.BWN_DISASM):
                return ui.AST_DISABLE_FOR_WIDGET
        return ui.AST_ENABLE_FOR_WIDGET


class DatabaseHooks(ida_idp.IDB_Hooks):
    def __init__(self, manager):
        super().__init__()
        self.manager = manager

    def byte_patched(self, ea, old_value):
        if self.manager.session:
            self.manager.session.invalidate()
        return 0

    def renamed(self, *args):
        if self.manager.session:
            self.manager.session.invalidate_names()
        return 0

    def segm_moved(self, *args):
        if self.manager.session:
            self.manager.session.invalidate()
        return 0

    def closebase(self):
        self.manager.close_database()
        return 0


class UIHooks(ui.UI_Hooks):
    def __init__(self,manager):
        super().__init__()
        self.manager = manager

    def preprocess_action(self, name):
        # Respect other architectures and unrelated Tab bindings (CLI, type lists).
        if name == 'wasm_decompiler:decompile' or ida_ida.inf_get_procname() != 'wasm':
            return 0
        widget = ui.get_current_widget()
        if self.manager.owns(widget):
            handlers = {'JumpAsk':self.manager.viewer.goto_address,
                        'JumpOpXref':self.manager.viewer.xrefs,
                        'JumpEnter':self.manager.viewer.follow,
                        'MakeName':self.manager.viewer.rename}
            if name in handlers:
                try:
                    handlers[name]()
                except (WasmError,OSError) as exc:
                    ui.warning(str(exc))
                return 1
        if ui.get_action_shortcut(name) == 'Tab' and widget and (self.manager.owns(widget) or ui.get_widget_type(widget) == ui.BWN_DISASM):
            try:
                self.manager.toggle(widget)
            except (WasmError,OSError) as exc:
                ui.warning(str(exc))
            return 1
        return 0

    def finish_populating_widget_popup(self, widget, popup, ctx=None):
        if ida_ida.inf_get_procname() == 'wasm' and ui.get_widget_type(widget) == ui.BWN_DISASM:
            ui.attach_action_to_popup(widget,popup,'wasm_decompiler:decompile')


class Manager:
    def __init__(self):
        self.session, self.views, self.actions = None,{},[]
        self.viewer, self.disassembly = None,None
        self.disassembly_ea = ida_idaapi.BADADDR
        self.dbhooks, self.uihooks = DatabaseHooks(self),UIHooks(self)

    def install(self):
        actions = {'decompile':'Toggle Wasm pseudocode/disassembly','back':'Previous pseudocode location','forward':'Next pseudocode location','refresh':'Refresh pseudocode','jump':'Jump to current Wasm instruction','goto':'Go to address or symbol','xrefs':'Cross-references to symbol','rename':'Rename symbol','export':'Export function pseudocode','export_module':'Export module pseudocode','stack_pointer':'Configure C stack pointer'}
        for action,label in actions.items():
            name = 'wasm_decompiler:'+action
            desc = ui.action_desc_t(name,label,Handler(self,action),'Tab' if action == 'decompile' else None)
            if ui.register_action(desc):
                self.actions.append(name)
        self.dbhooks.hook()
        self.uihooks.hook()
        ui.attach_action_to_menu('Edit/Plugins/','wasm_decompiler:decompile',ui.SETMENU_APP)

    def ensure_session(self):
        if ida_ida.inf_get_procname() != 'wasm':
            raise WasmError('open a WebAssembly database first')
        if self.session is None:
            self.session = Session()
        return self.session

    def owns(self, widget):
        return bool(widget and self.viewer and self.viewer.GetWidget() == widget)

    def open_function(self, index):
        self.ensure_session()
        if self.viewer is None:
            view = Viewer(self,index)
            if not view.create():
                raise WasmError('could not create pseudocode viewer')
            self.viewer = view
            self.views[index] = view
        else:
            self.viewer.navigate(index)
        self.viewer.Show()
        ui.activate_widget(self.viewer.GetWidget(), True)

    def toggle(self, widget=None):
        widget = widget or ui.get_current_widget()
        session = self.ensure_session()
        if self.owns(widget):
            viewer = self.viewer
            position = viewer.GetPos()
            offsets = viewer.line_map.get(position[0],[]) if position else []
            f = session.module.functions[viewer.index]
            ea = self.disassembly_ea if f.imported else session.ea(offsets[0] if offsets else f.code_offset)
            if self.disassembly:
                ui.activate_widget(self.disassembly,True)
            if ea != ida_idaapi.BADADDR:
                ui.jumpto(ea)
            return
        if not widget or ui.get_widget_type(widget) != ui.BWN_DISASM:
            return
        self.disassembly = widget
        self.disassembly_ea = ui.get_screen_ea()
        session.update()
        try:
            index = session.function_at(ui.get_screen_ea())
        except WasmError:
            if self.viewer:
                self.viewer.Show()
                ui.activate_widget(self.viewer.GetWidget(),True)
                return
            raise
        self.open_function(index)

    def current_ea(self,viewer):
        position = viewer.GetPos()
        offsets = viewer.line_map.get(position[0],[]) if position else []
        function = self.session.module.functions[viewer.index]
        if offsets:
            return self.session.ea(offsets[0])
        return self.session.symbols.function_ea(function.index)

    def show_disassembly(self,ea):
        if ea == ida_idaapi.BADADDR:
            return
        self.disassembly_ea = ea
        if self.disassembly:
            ui.activate_widget(self.disassembly,True)
        ui.jumpto(ea)

    def navigate_address(self,ea):
        session = self.ensure_session()
        try:
            index = session.function_at(ea)
        except WasmError:
            self.show_disassembly(ea)
            return
        if self.viewer and self.viewer.index == index:
            self.viewer.history.append((index,self.viewer.GetPos()))
            self.viewer.future.clear()
        self.open_function(index)
        offset = ida_loader.get_fileregion_offset(ea)
        candidates = [(min(abs(value-offset) for value in values),line)
                      for line,values in self.viewer.line_map.items() if values]
        if candidates:
            self.viewer.Jump(min(candidates)[1])

    def dispatch(self, action, ctx):
        session = self.ensure_session()
        widget = getattr(ctx,'widget',None)
        view = next((v for v in self.views.values() if v.GetWidget() == widget),None)
        if action == 'decompile':
            self.toggle(widget)
        elif action in ('back','forward') and view:
            view.back(forward=action == 'forward')
        elif action == 'export_module':
            self.export(None)
        elif action == 'stack_pointer':
            value = ui.ask_str(str(session.settings.get('stack_pointer') if session.settings.get('stack_pointer') is not None else 'auto'),0,'C stack pointer global index, or auto')
            if value is not None:
                idx = None if value.strip() == 'auto' else int(value,0)
                if idx is not None and (idx < 0 or idx >= len(session.module.globals) or session.module.globals[idx]['type'] != 'i32' or not session.module.globals[idx]['mutable']):
                    raise WasmError('stack pointer must name a mutable i32 global')
                session.settings['stack_pointer'] = idx
                session.save()
                session.invalidate()
                for v in list(self.views.values()):
                    v.refresh_result()
        elif view:
            if action == 'refresh':
                session.invalidate()
                view.refresh_result()
            elif action == 'jump':
                view.jump()
            elif action == 'goto':
                view.goto_address()
            elif action == 'xrefs':
                view.xrefs()
            elif action == 'rename':
                view.rename()
            elif action == 'export':
                self.export(view)

    def export(self, view):
        session = self.ensure_session()
        path = ui.ask_file(True,'*.c','Export Wasm pseudocode')
        if not path:
            return
        ui.show_wait_box('Decompiling WebAssembly; Cancel stops export')
        try:
            session.update()
            indices = [view.index] if view else range(len(session.module.functions))
            results = []
            for index in indices:
                if ui.user_cancelled():
                    raise WasmError('export cancelled',code='cancelled')
                results.append(session.result(index))
            if ui.user_cancelled():
                raise WasmError('export cancelled',code='cancelled')
            Path(path).write_text(export_text(session.module,results,session.names(),session.global_names()),encoding='utf-8')
            failures = sum(not r.success for r in results)
            ui.msg(f'Wasm decompiler: exported {len(results)} functions to {path}; {failures} failed (diagnostics included).\n')
        finally:
            ui.hide_wait_box()

    def close_database(self):
        for view in list(self.views.values()):
            view.Close()
        self.views.clear()
        self.viewer, self.disassembly = None,None
        self.disassembly_ea = ida_idaapi.BADADDR
        self.session = None

    def uninstall(self):
        self.close_database()
        self.uihooks.unhook()
        self.dbhooks.unhook()
        for action in self.actions:
            ui.unregister_action(action)
        self.actions.clear()
