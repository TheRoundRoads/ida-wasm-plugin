"""Run by IDA -S, not by a normal Python interpreter."""
import json
import os
from pathlib import Path
import sys
import traceback
import re

ROOT = Path(os.environ['WASM_PLUGIN_ROOT'])
sys.path.insert(0,str(ROOT))
import ida_hexrays
original_native_decompile = ida_hexrays.decompile

import ida_auto
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin as ui
import ida_loader
import ida_name
import ida_pro
import ida_lines
import ida_xref
import idautils

report = {'checks':[]}
manager = None
try:
    ida_auto.auto_wait()
    import ida_wasm_decompiler as wasm_api
    from wasm_decompiler.ida_plugin import Manager,Session,get_session
    api_session = get_session()
    first_defined = next(f for f in api_session.module.functions if not f.imported)
    api_ea = api_session.ea(first_defined.code_offset)
    api_result = wasm_api.decompile(api_ea)
    assert api_result.entry_ea == api_ea
    assert api_result.function_index == first_defined.index
    assert str(api_result) == api_result.text
    assert api_result.get_warnings() == api_result.diagnostics
    assert [line.line for line in api_result.get_pseudocode()] == api_result.text.splitlines()
    assert any(line.eas for line in api_result.get_pseudocode())
    assert wasm_api.decompile(ida_funcs.get_func(api_ea)).text == api_result.text
    printer = wasm_api.WasmPrinter(api_result)
    assert api_result.print_func(printer) is None and printer.get_s() == api_result.text
    assert wasm_api.decompile_many([api_ea])[0].text == api_result.text
    assert api_result.name in wasm_api.export_text([api_ea])
    api_export = Path(os.environ['WASM_TEST_REPORT']).with_suffix('.api.c')
    assert wasm_api.export_file(api_export, [api_ea]) == api_export
    assert api_result.name in api_export.read_text()
    for line, offsets in api_result.source_map.items():
        assert api_result.ea_map[line] == tuple(api_session.ea(offset) for offset in offsets)
    try:
        wasm_api.decompile(ida_idaapi.BADADDR)
        raise AssertionError('invalid address accepted')
    except wasm_api.WasmError:
        pass
    report['checks'].append('headless IDAPython decompilation API and text facade')
    manager = Manager()
    manager.install()
    assert ida_hexrays.decompile is original_native_decompile
    report['checks'].append('actions registered')
    assert ui.get_action_label('wasm_decompiler:decompile')
    session = manager.ensure_session()
    assert session is api_session
    if os.environ.get('WASM_TEST_REOPEN') == '1':
        assert any('persisted_local' in names.values() for names in session.settings['locals'].values())
        report['checks'].append('saved database reopened with settings')
    selected = os.environ.get('WASM_TEST_FUNCTIONS','')
    selected = {int(i) for i in selected.split(',')} if selected else None
    for f in session.module.functions:
        if selected is not None and f.index not in selected:
            continue
        if f.imported:
            continue
        ea = session.ea(f.code_offset)
        assert ea != ida_idaapi.BADADDR
        assert session.function_at(ea) == f.index
        result = session.result(f.index)
        assert result.success, result.diagnostics
        for offsets in result.source_map.values():
            assert all(session.ea(off) != ida_idaapi.BADADDR for off in offsets)
    from wasm_decompiler.references import collect_references
    expected_refs,_ = collect_references(session.module)
    expected = {}
    for offset,kind,gi in expected_refs:
        if kind == 'call':
            continue
        source = ida_bytes.get_item_head(session.ea(offset))
        target = session.symbols.global_ea(gi)
        if (source,target) not in expected or kind=='write':
            expected[source,target] = ida_xref.dr_W if kind=='write' else ida_xref.dr_R
    actual_refs = {(x.frm,session.symbols.global_ea(gi)):x.type
                   for gi in range(len(session.module.globals))
                   for x in idautils.XrefsTo(session.symbols.global_ea(gi),0)}
    for (source,target),kind in expected.items():
        assert actual_refs.get((source,target)) == kind, (hex(source),hex(target),kind)
    report['checks'].append('all global read/write refs attach to actual IDA instruction heads')
    report['checks'].append('selected functions and source maps' if selected else 'all functions and source maps')
    index = next(f.index for f in session.module.functions if not f.imported)
    f = session.module.functions[index]
    ea = session.ea(f.code_offset)
    assert ida_name.set_name(ea,'integration_renamed',ida_name.SN_CHECK)
    assert session.result(index).name == 'integration_renamed'
    assert wasm_api.decompile(ea).name == 'integration_renamed'
    if index == api_result.function_index and os.environ.get('WASM_TEST_REOPEN') != '1':
        assert api_result.name != 'integration_renamed'
    report['checks'].append('database rename invalidates names')
    owned_before = [(x.frm,x.to,x.type) for gi in range(len(session.module.globals))
                    for x in idautils.XrefsTo(session.symbols.global_ea(gi),0) if x.frm==ea]
    retained_user_ref = None
    if session.module.globals:
        retained_user_ref = (session.ea(0),session.symbols.global_ea(0))
        assert ida_xref.add_dref(*retained_user_ref,ida_xref.dr_R | ida_xref.XREF_USER)
    original = ida_bytes.get_byte(ea)
    ida_bytes.patch_byte(ea,0xfd)
    assert not session.result(index).success
    try:
        wasm_api.decompile(ea)
        raise AssertionError('unsupported instruction accepted by API')
    except wasm_api.WasmError as exc:
        assert exc.code == 'unsupported'
    for frm,to,xtype in owned_before:
        assert not any(x.frm==frm for x in idautils.XrefsTo(to,0))
    if retained_user_ref:
        assert any(x.frm==retained_user_ref[0] for x in idautils.XrefsTo(retained_user_ref[1],0))
    ida_bytes.patch_byte(ea,original)
    assert session.result(index).success
    assert wasm_api.decompile(ea).text
    for frm,to,xtype in owned_before:
        assert any(x.frm==frm and x.type==xtype for x in idautils.XrefsTo(to,0))
    report['checks'].append('byte patch invalidation, owned xref replacement and user xref preservation')
    # Replacing the last instruction with an unknown opcode is diagnosed in only this function.
    metadata_ea = session.ea(0)
    ida_bytes.patch_byte(metadata_ea,1)
    try:
        session.result(index)
        raise AssertionError('structural patch accepted')
    except ValueError:
        pass
    ida_bytes.patch_byte(metadata_ea,0)
    assert session.result(index).success
    report['checks'].append('structural patches rejected')
    if os.environ.get('WASM_TEST_GUI') == '1':
        manager.open_function(index)
        viewer = manager.views[index]
        assert viewer.GetWidget()
        assert viewer.Count() > 1
        viewer.OnKeydown(ord('R'),0)
        # Follow a known mapped line into disassembly.
        line = next(iter(viewer.line_map))
        viewer.Jump(line,0,0)
        viewer.jump()
        report['checks'].append('viewer create, refresh and navigation')
        if hasattr(ui.PluginForm,'TWidgetToQtPythonWidget'):
            from PySide6.QtCore import Qt,QEvent
            from PySide6.QtGui import QKeyEvent
            from PySide6.QtWidgets import QApplication
            to_qt = ui.PluginForm.TWidgetToQtPythonWidget
        else:
            from PyQt5.QtCore import Qt,QEvent
            from PyQt5.QtGui import QKeyEvent
            from PyQt5.QtWidgets import QApplication
            to_qt = ui.PluginForm.TWidgetToPyQtWidget
        assert ui.get_action_shortcut('wasm_decompiler:decompile') == 'Tab'
        disassembly = ui.find_widget('IDA View-A')
        assert disassembly
        ui.activate_widget(disassembly,True)
        ui.jumpto(ea)
        QApplication.processEvents()
        qt_disassembly = to_qt(disassembly)
        qt_disassembly.window().show()
        QApplication.setActiveWindow(qt_disassembly.window())
        qt_disassembly.setFocus()
        QApplication.processEvents()
        assert ui.get_widget_type(ui.get_current_widget()) == ui.BWN_DISASM, ('focus before Tab',ui.get_widget_title(ui.get_current_widget()))
        QApplication.sendEvent(qt_disassembly.focusWidget() or qt_disassembly,QKeyEvent(QEvent.KeyPress,Qt.Key_Tab,Qt.NoModifier))
        QApplication.processEvents()
        assert manager.owns(ui.get_current_widget()), 'Tab did not activate pseudocode'
        assert manager.viewer is viewer and len(manager.views) == 1
        qt_view = to_qt(viewer.GetWidget())
        QApplication.sendEvent(qt_view.focusWidget() or qt_view,QKeyEvent(QEvent.KeyPress,Qt.Key_Tab,Qt.NoModifier))
        QApplication.processEvents()
        assert ui.get_widget_type(ui.get_current_widget()) == ui.BWN_DISASM, 'Tab did not return to disassembly'
        report['checks'].append('real Tab key toggles both directions')
        # Resolve actual rendered identifier columns. Never mock GetCurrentWord:
        # the real API returns whitespace chunks such as `_f1387(0);`.
        def point_at(name, require_call=False):
            pattern = re.compile(r'\b'+re.escape(name)+(r'(?=\()' if require_call else r'\b'))
            for row in range(1,viewer.Count()):
                text = ida_lines.tag_remove(viewer.GetLine(row)[0])
                match = pattern.search(text)
                if match:
                    viewer.Jump(row,match.start()+len(name)//2)
                    QApplication.processEvents()
                    return row
            raise AssertionError('symbol missing from rendered view: '+name)

        requested_follow = os.environ.get('WASM_TEST_FOLLOW','')
        if requested_follow:
            caller,target = map(int,requested_follow.split(':'))
        else:
            caller = next((f.index for f in session.module.functions if not f.imported and
                           any(sym['kind']=='function' and sym['index'] != f.index for sym in session.result(f.index).symbols.values())),None)
            target = None
        if caller is not None:
            manager.open_function(caller)
            if target is None:
                target = next(sym['index'] for sym in viewer.result.symbols.values() if sym['kind']=='function' and sym['index']!=caller)
            target_ea = session.symbols.function_ea(target)
            original_name = ida_name.get_name(target_ea) if target_ea != ida_idaapi.BADADDR else ''
            if not session.module.functions[target].imported:
                occupied = ida_name.get_name_ea(ida_idaapi.BADADDR,'_f1387')
                if occupied in (ida_idaapi.BADADDR,target_ea):
                    assert ida_name.set_name(target_ea,'_f1387',ida_name.SN_CHECK)
            manager.open_function(caller)
            target_name = next(name for name,sym in viewer.result.symbols.items() if sym['kind']=='function' and sym['index']==target)
            point_at(target_name,True)
            assert viewer.resolve_symbol()[1]['index'] == target
            caller_position = viewer.GetPos()
            viewer.OnKeydown(13,0)
            assert viewer.index == target and manager.viewer is viewer and len(manager.views)==1
            viewer.OnKeydown(27,0)
            assert viewer.index == caller and viewer.GetPos() == caller_position
            # Mouse not over this offscreen view: the actual cursor identifier is used.
            viewer.OnDblClick(0)
            assert viewer.index == target and manager.viewer is viewer
            viewer.OnKeydown(37,ui.VES_ALT)
            assert viewer.index == caller
            if original_name:
                assert ida_name.set_name(target_ea,original_name,ida_name.SN_CHECK)
            report['checks'].append('real identifier hit-testing: Enter/double-click follow _f1387; history restores caller')
        manager.open_function(index)
        local = next((name for name,s in viewer.result.symbols.items() if s['kind']=='local' and any(re.search(r'\b'+re.escape(name)+r'\b',ida_lines.tag_remove(viewer.GetLine(row)[0])) for row in range(viewer.Count()))),None)
        if local:
            point_at(local)
            ask = ui.ask_str
            ui.ask_str = lambda *args:'integration_local'
            try:
                viewer.rename()
            finally:
                ui.ask_str = ask
            assert 'integration_local' in viewer.result.text
            report['checks'].append('viewer local rename with actual cursor hit-testing')

        # G opens the address dialog, and mapped code addresses open pseudocode.
        ask_addr = ui.ask_addr
        address_target = next(f for f in session.module.functions if not f.imported and f.index != index)
        ui.ask_addr = lambda *args:session.ea(address_target.code_offset)
        try:
            viewer.OnKeydown(ord('G'),0)
        finally:
            ui.ask_addr = ask_addr
        assert viewer.index == address_target.index
        assert viewer.GetPos()[0] in viewer.line_map
        previous_position = viewer.GetPos()
        manager.navigate_address(session.ea(address_target.code_offset))
        assert viewer.back() and viewer.GetPos() == previous_position
        report['checks'].append('G address dialog routes code addresses to pseudocode with location history')
        manager.open_function(index)

        # Globals have durable addresses and actual kernel read/write xrefs.
        global_symbols = [(name,sym) for f in session.module.functions if not f.imported and (selected is None or f.index in selected)
                          for name,sym in session.result(f.index).symbols.items() if sym['kind']=='global']
        if global_symbols:
            global_name,global_symbol = global_symbols[0]
            global_index = global_symbol['index']
            global_ea = session.symbols.global_ea(global_index)
            assert ida_name.get_name(global_ea)
            references = list(idautils.XrefsTo(global_ea,0))
            assert any(x.type in (ida_xref.dr_R,ida_xref.dr_W) for x in references)
            source = next(x.frm for x in references if any(not f.imported and f.code_offset <= ida_loader.get_fileregion_offset(x.frm) < f.code_offset+len(f.code) for f in session.module.functions))
            manager.navigate_address(source)
            name = session.global_names()[global_index]
            point_at(name)
            assert viewer.resolve_symbol()[1]['ea'] == global_ea
            choose_xref = ui.choose_xref
            selected_targets = []
            ui.choose_xref = lambda ea:(selected_targets.append(ea) or source)
            try:
                viewer.OnKeydown(ord('X'),0)
            finally:
                ui.choose_xref = choose_xref
            assert selected_targets == [global_ea]
            assert viewer.index == session.function_at(source)
            data_dialog = ui.ask_addr
            ui.ask_addr = lambda *args:global_ea
            try:
                viewer.OnKeydown(ord('G'),0)
            finally:
                ui.ask_addr = data_dialog
            assert ui.get_screen_ea() == global_ea
            manager.toggle(ui.get_current_widget())
            assert manager.owns(ui.get_current_widget())
            old_name = ida_name.get_name(global_ea)
            assert ida_name.set_name(global_ea,'integration_global',ida_name.SN_CHECK)
            viewer.refresh_result()
            assert 'integration_global' in viewer.result.text
            assert viewer.result.symbols['integration_global']['ea'] == global_ea
            assert ida_name.set_name(global_ea,old_name,ida_name.SN_CHECK)
            report['checks'].append('global identities, kernel xrefs, X chooser routing and database renames')
        manager.open_function(index)
        old_ask_file = ui.ask_file
        export_path = Path(os.environ['WASM_TEST_REPORT']).with_suffix('.c')
        ui.ask_file = lambda *args:str(export_path)
        try:
            manager.export(viewer if selected else None)
        finally:
            ui.ask_file = old_ask_file
        assert export_path.is_file() and 'integration_renamed' in export_path.read_text()
        report['checks'].append('interactive module export')
        viewer.Close()
        assert index not in manager.views
        manager.open_function(index)
        report['checks'].append('viewer close and reopen')
    session.settings['locals'].setdefault(str(index),{})['0'] = 'persisted_local'
    session.save()
    reopened = Session()
    assert reopened.settings['locals'][str(index)]['0'] == 'persisted_local'
    report['checks'].append('netnode settings and original module persistence')
    manager.uninstall()
    manager = None
    assert wasm_api.decompile(ea).text
    report['checks'].append('action and hook cleanup')
    # Exercise the actual plugin entry point through IDA's plugin loader.
    plugin = ida_loader.load_plugin(str(ROOT/'ida_wasm_decompiler.py'))
    assert plugin is not None
    assert ui.get_action_label('wasm_decompiler:decompile')
    assert ida_hexrays.decompile is original_native_decompile
    report['checks'].append('plugin loaded without replacing the native Hex-Rays API')
    report['ok'] = True
except Exception:
    report['ok'] = False
    report['error'] = traceback.format_exc()
finally:
    if manager:
        manager.uninstall()
    Path(os.environ['WASM_TEST_REPORT']).write_text(json.dumps(report,indent=2))
    ida_pro.qexit(0 if report.get('ok') else 1)
