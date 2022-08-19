"""
User Interface module

This module exposes a number of tools and class definitions for
interacting with IDA's user interface. This includes things such
as getting the current state of user input, information about
windows that are in use as well as utilities for simplifying the
customization of the interface.

There are a few namespaces that are provided in order to get the
current state. The ``ui.current`` namespace allows for one to get
the current address, function, segment, window, as well as a number
of other things.

A number of namespaces defined within this module also allows a
user to interact with the different windows that are currently
in use. This can allow for one to automatically show or hide a
window that they wish to expose to the user.
"""

import six, builtins
import sys, os, operator, math, threading, time, functools, inspect, itertools
import logging, ctypes

import idaapi, internal
import database as _database, segment as _segment

## TODO:
# locate window under current cursor position
# pop-up a menu item
# pop-up a form/messagebox
# another item menu to toolbar
# find the QAction associated with a command (or keypress)

class application(object):
    """
    This namespace is for getting information about the application user-interface.
    """
    def __new__(cls):
        '''Return the current instance of the application.'''
        raise internal.exceptions.MissingMethodError

    @classmethod
    def window(cls):
        '''Return the current window for the application.'''
        raise internal.exceptions.MissingMethodError

    @classmethod
    def windows(cls):
        '''Return all of the top-level windows for the application.'''
        raise internal.exceptions.MissingMethodError

    @classmethod
    def beep(cls):
        '''Beep using the application interface.'''
        return idaapi.beep()
beep = internal.utils.alias(application.beep, 'application')

class ask(object):
    """
    This namespace contains utilities for asking the user for some
    particular type of information. These will typically require a
    user-interface of some sort and will block while waiting for the
    user to respond.

    If the `default` parameter is specified to any of the functions
    within this namespace, then its value will be used by default
    in the inbox that is displayed to the user.
    """
    @internal.utils.multicase()
    def __new__(cls, **default):
        '''Request the user choose from the options "yes", "no", or "cancel".'''
        return cls(u'', **default)
    @internal.utils.multicase(message=six.string_types)
    def __new__(cls, message, **default):
        '''Request the user choose from the options "yes", "no", or "cancel" using the specified `message` as the prompt.'''
        return cls.yn(message, **default)

    @internal.utils.multicase()
    @classmethod
    def yn(cls, **default):
        '''Request the user choose from the options "yes", "no", or "cancel".'''
        return cls.yn(u'', **default)
    @internal.utils.multicase(message=six.string_types)
    @classmethod
    @internal.utils.string.decorate_arguments('message')
    def yn(cls, message, **default):
        """Request the user choose from the options "yes", "no", or "cancel" using the specified `message` as the prompt.

        If any of the options are specified as a boolean, then it is
        assumed that this option will be the default. If the user
        chooses "cancel", then this value will be returned instead of
        the value ``None``.
        """
        state = {'no': getattr(idaapi, 'ASKBTN_NO', 0), 'yes': getattr(idaapi, 'ASKBTN_YES', 1), 'cancel': getattr(idaapi, 'ASKBTN_CANCEL', -1)}
        results = {state['no']: False, state['yes']: True}
        if default:
            keys = {item for item in default.keys()}
            keys = {item.lower() for item in keys if default.get(item, False)}
            dflt = next((item for item in keys), 'cancel')
        else:
            dflt = 'cancel'
        res = idaapi.ask_yn(state[dflt], internal.utils.string.to(message))
        return results.get(res, None)

    @internal.utils.multicase()
    @classmethod
    def address(cls, **default):
        '''Request the user provide an address.'''
        return cls.address(u'', **default)
    @internal.utils.multicase(message=six.string_types)
    @classmethod
    @internal.utils.string.decorate_arguments('message')
    def address(cls, message, **default):
        """Request the user provide an address using the specified `message` as the prompt.

        If the `valid` parameter is specified, then verify that the
        address is within the bounds of the database. If the `bounds`
        parameter is specified, then verify that the address chosen
        by the user is within the provided bounds.
        """
        dflt = next((default[k] for k in ['default', 'address', 'ea', 'addr'] if k in default), current.address())

        # Ask the user for an address...
        ea = idaapi.ask_addr(dflt, internal.utils.string.to(message))

        # If we received idaapi.BADADDR, then the user gave us a bogus
        # value that we need to return None for.
        if ea == idaapi.BADADDR:
            return None

        # Grab the bounds that we'll need to compare the address to from
        # the parameters or the database configuration.
        bounds = next((default[k] for k in ['bounds'] if k in default), _database.config.bounds())

        # If we were asked to verify the address, or we were given some
        # boundaries to check it against..then do that here.
        if default.get('verify', 'bounds' in default):
            l, r = bounds
            return ea if l <= ea < r else None

        # Otherwise, we can just return the address here.
        return ea

    @internal.utils.multicase()
    @classmethod
    def integer(cls, **default):
        '''Request the user provide an integer.'''
        return cls.integer(u'', **default)
    @internal.utils.multicase(message=six.string_types)
    @classmethod
    @internal.utils.string.decorate_arguments('message')
    def integer(cls, message, **default):
        '''Request the user provide an integer using the specified `message` as the prompt.'''
        dflt = next((default[k] for k in ['default', 'integer', 'long', 'int'] if k in default), getattr(cls, '__last_integer__', 0))

        # Ask the user for some kind of integer...
        integer = idaapi.ask_long(dflt, internal.utils.string.to(message))

        # If we actually received an integer, then cache it so that we can
        # reuse it as the default the next time this function gets called.
        if integer is not None:
            cls.__last_integer__ = integer

        return integer

    @internal.utils.multicase()
    @classmethod
    def segment(cls, **default):
        '''Request the user provide a segment.'''
        return cls.segment(u'', **default)
    @internal.utils.multicase(message=six.string_types)
    @classmethod
    @internal.utils.string.decorate_arguments('message')
    def segment(cls, message, **default):
        '''Request the user provide a segment using the specified `message` as the prompt.'''
        res = current.segment()
        dflt = next((default[k] for k in ['default', 'segment', 'seg'] if k in default), internal.interface.range.start(res) if res else idaapi.BADADDR)
        ea = idaapi.ask_seg(dflt, internal.utils.string.to(message))

        # Try and convert whatever it was that we were given into an actual segment.
        try:
            seg = _segment.by(ea)

        # If we got an exception, then just set our result to None so that we can
        # let the caller figure out how much they really want it.
        except Exception:
            return None

        # Return the segment_t back to the caller.
        return seg

    @internal.utils.multicase()
    @classmethod
    def string(cls, **default):
        '''Request the user provide a string.'''
        return cls.string(u'', **default)
    @internal.utils.multicase(message=six.string_types)
    @classmethod
    @internal.utils.string.decorate_arguments('message', 'default', 'text', 'string')
    def string(cls, message, **default):
        '''Request the user provide a string using the specified `message` as the prompt.'''
        dflt = next((default[k] for k in ['default', 'text', 'string'] if k in default), None) or u''

        # FIXME: we should totally expose the history id to the caller in some
        #        way.. but after some fiddling around with it, I can't seem to
        #        make it actually do anything.

        result = idaapi.ask_str(internal.utils.string.to(dflt), idaapi.HIST_IDENT, internal.utils.string.to(message))
        return internal.utils.string.of(result)

    @internal.utils.multicase()
    @classmethod
    def note(cls, **default):
        '''Request the user provide a multi-lined string.'''
        return cls.note(u'', **default)
    @internal.utils.multicase(message=six.string_types)
    @classmethod
    @internal.utils.string.decorate_arguments('message', 'default', 'text', 'string')
    def note(cls, message, **default):
        """Request the user provide a multi-lined string using the specified `message` as the prompt.

        If the `length` parameter is provided as an integer, then constrain
        the length of the user's input to the integer that was specified.
        """
        dflt = next((default[k] for k in ['default', 'text', 'string'] if k in default), None) or u''
        length = next((default[k] for k in ['length', 'max', 'maxlength'] if k in default), 0)
        result = idaapi.ask_text(length, internal.utils.string.to(dflt), internal.utils.string.to(message))
        return internal.utils.string.of(result)

class current(object):
    """
    This namespace contains tools for fetching information about the
    current selection state. This can be used to get the state of
    thigns that are currently selected such as the address, function,
    segment, clipboard, widget, or even the current window in use.
    """
    @classmethod
    def address(cls):
        '''Return the current address.'''
        return idaapi.get_screen_ea()
    @classmethod
    def color(cls):
        '''Return the color of the current item.'''
        ea = cls.address()
        return idaapi.get_item_color(ea)
    @classmethod
    def function(cls):
        '''Return the current function.'''
        ea = cls.address()
        res = idaapi.get_func(ea)
        if res is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}.function() : Unable to find a function at the current location.".format('.'.join([__name__, cls.__name__])))
        return res
    @classmethod
    def segment(cls):
        '''Return the current segment.'''
        ea = cls.address()
        return idaapi.getseg(ea)
    @classmethod
    def status(cls):
        '''Return the IDA status.'''
        # TODO: grab the current status and return it in some form
        raise internal.exceptions.UnsupportedCapability(u"{:s}.status() : Unable to get the current disassembler status.".format('.'.join([__name__, cls.__name__])))
    @classmethod
    def symbol(cls):
        '''Return the current highlighted symbol name or register.'''
        if idaapi.__version__ < 7.0:
            return idaapi.get_highlighted_identifier()

        HIF_IDENTIFIER, HIF_REGISTER = getattr(idaapi, 'HIF_IDENTIFIER', 1), getattr(idaapi, 'HIF_REGISTER', 2)

        # IDA 7.0 way of getting the currently selected text
        viewer = idaapi.get_current_viewer()
        identifier_and_flags = idaapi.get_highlight(viewer)
        if identifier_and_flags is None:
            return None
        identifier, flags = identifier_and_flags

        # If it wasn't a register, then we can just return the identifier as a string.
        if flags & HIF_REGISTER == 0:
            return identifier

        # Otherwise we need to lookup our identifier in the current architecture.
        import instruction
        try:
            res = instruction.architecture.by_name(identifier)

        # If we got an exception, then only log a warning if the architecture is known.
        except Exception as E:
            if hasattr(instruction, 'architecture'):
                architecture = instruction.architecture.__class__
                logging.warning(u"{:s}.symbol(): Returning a string due to the returned identifier (\"{:s}\") not being available within the current architecture ({:s}).".format('.'.join([__name__, cls.__name__]), identifier, architecture.__name__))
            return identifier
        return res
    @classmethod
    def selection(cls):
        '''Return the current address range of whatever is selected'''
        view = idaapi.get_current_viewer()
        left, right = idaapi.twinpos_t(), idaapi.twinpos_t()

        # If we were able to grab a selection, then return it.
        if idaapi.read_selection(view, left, right):
            pl_l, pl_r = left.place(view), right.place(view)
            ea_l, ea_r = pl_l.ea, pl_r.ea
            l, r = internal.interface.address.inside(ea_l, ea_r)
            return internal.interface.bounds_t(l, r + 1)

        # Otherwise we just use the current address for both sides.
        ea = idaapi.get_screen_ea()
        ea_l, ea_r = ea, ea
        return internal.interface.bounds_t(ea_l, ea_r)
    selected = internal.utils.alias(selection, 'current')
    @classmethod
    def operand(cls):
        '''Return the currently selected operand number.'''
        return idaapi.get_opnum()
    opnum = internal.utils.alias(operand, 'current')
    @classmethod
    def widget(cls):
        '''Return the current widget that is being used.'''
        if hasattr(idaapi, 'get_current_widget'):
            return idaapi.get_current_widget()

        # XXX: there's probably a better way to do this rather than looking
        #      at the mouse cursor position
        x, y = mouse.position()
        return widget.at((x, y))
    @classmethod
    def window(cls):
        '''Return the current window that is being used.'''
        return application.window()
    @classmethod
    def viewer(cls):
        '''Return the current viewer that is being used.'''
        return idaapi.get_current_viewer()

class state(object):
    """
    This namespace is for fetching or interacting with the current
    state of IDA's interface. These are things such as waiting for
    IDA's analysis queue, or determining whether the function is
    being viewed in graph view or not.
    """
    @classmethod
    def graphview(cls):
        '''Returns true if the current function is being viewed in graph view mode.'''
        res = idaapi.get_inf_structure()
        if idaapi.__version__ < 7.0:
            return res.graph_view != 0
        return res.is_graph_view()

    @classmethod
    def wait(cls):
        '''Wait until IDA's autoanalysis queues are empty.'''
        return idaapi.autoWait() if idaapi.__version__ < 7.0 else idaapi.auto_wait()
wait = internal.utils.alias(state.wait, 'state')

class message(object):
    """
    This namespace is for displaying a modal dialog box with the different
    icons that are available from IDA's user interface. The functions within
    will block IDA from being interacted with while their dialog is displayed.
    """
    def __new__(cls, message, **icon):
        '''Display a modal information dialog box using the provided `message`.'''
        if not idaapi.is_msg_inited():
            raise internal.exceptions.DisassemblerError(u"{:s}({!r}{:s}) : Unable to display the requested modal dialog due to the user interface not yet being initialized.".format('.'.join([__name__, cls.__name__]), message, ", {:s}".format(internal.utils.string.kwargs(icon)) if icon else ''))

        # because ida is fucking hil-ar-ious...
        def why(F, *args):
            name = '.'.join([F.__module__, F.__name__] if hasattr(F, '__module__') else [F.__name__])
            raise internal.exceptions.DisassemblerError(u"{:s}({!r}{:s}) : Refusing to display the requested modal dialog with `{:s}` due it explicitly terminating the host application.".format('.'.join([__name__, cls.__name__]), message, ", {:s}".format(internal.utils.string.kwargs(icon)) if icon else '', name))

        # these are all of the ones that seem to be available.
        mapping = {
            'information': idaapi.info, 'info': idaapi.info,
            'warning': idaapi.warning, 'warn': idaapi.warning,
            'error': functools.partial(why, idaapi.error), 'fatal': functools.partial(why, idaapi.error),
            'nomem': functools.partial(why, idaapi.nomem), 'fuckyou': functools.partial(why, idaapi.nomem),
        }
        F = builtins.next((mapping[k] for k in icon if mapping.get(k, False)), idaapi.info)

        # format it and give a warning if it's not the right type.
        formatted = message if isinstance(message, six.string_types) else "{!s}".format(message)
        if not isinstance(message, six.string_types):
            logging.warning(u"{:s}({!r}{:s}) : Formatted the given message ({!r}) as a string ({!r}) prior to displaying it.".format('.'.join([__name__, cls.__name__]), message, ", {:s}".format(internal.utils.string.kwargs(icon)) if icon else '', message, formatted))

        # set it off...
        return F(internal.utils.string.to(formatted))

    @classmethod
    def information(cls, message):
        '''Display a modal information dialog box using the provided `message`.'''
        return cls(message, information=True)
    info = internal.utils.alias(information, 'message')

    @classmethod
    def warning(cls, message):
        '''Display a modal warning dialog box using the provided `message`.'''
        return cls(message, warning=True)
    warn = internal.utils.alias(warning, 'message')

    @classmethod
    def error(cls, message):
        '''Display a modal error dialog box using the provided `message`.'''
        return cls(message, error=True)

class appwindow(object):
    """
    Base namespace used for interacting with the windows provided by IDA.
    """
    @classmethod
    def open(cls, *args):
        '''Open or show the window belonging to the namespace.'''
        global widget
        res = cls.__open__(*args) if args else cls.__open__(*getattr(cls, '__open_defaults__', ()))
        return widget.of(res)

    @classmethod
    def close(cls):
        '''Close or hide the window belonging to the namespace.'''
        res = cls.open()
        return res.deleteLater()

class breakpoints(appwindow):
    """
    This namespace is for interacting with the Breakpoints window.
    """
    __open__ = staticmethod(idaapi.open_bpts_window)
    __open_defaults__ = (idaapi.BADADDR, 0)

class calls(appwindow):
    """
    This namespace is for interacting with the (Function) Calls window.
    """
    __open__ = staticmethod(idaapi.open_calls_window)
    __open_defaults__ = (idaapi.BADADDR, 0)

class disassembly(appwindow):
    """
    This namespace is for interacting with the Disassembly window.
    """
    __open__ = staticmethod(idaapi.open_disasm_window)
    __open_defaults__ = ('Disassembly', )

    @classmethod
    def refresh(cls):
        '''Refresh the main IDA disassembly view.'''
        return idaapi.refresh_idaview_anyway()
disassembler = disassembly

class dump(appwindow):
    """
    This namespace is for interacting with the (Hex) Dump window.
    """
    __open__ = staticmethod(idaapi.open_hexdump_window)
    __open_defaults__ = (idaapi.BADADDR, 0)
hexdump = dump

class enumerations(appwindow):
    """
    This namespace is for interacting with the Enumerations window.
    """
    __open__ = staticmethod(idaapi.open_enums_window)
    __open_defaults__ = (idaapi.BADADDR, 0)

class exports(appwindow):
    """
    This namespace is for interacting with the Exports window.
    """
    __open__ = staticmethod(idaapi.open_exports_window)
    __open_defaults__ = (idaapi.BADADDR, )

class frame(appwindow):
    """
    This namespace is for interacting with the (Function) Frame window.
    """
    __open__ = staticmethod(idaapi.open_frame_window)
    __open_defaults__ = (idaapi.BADADDR, )

class functions(appwindow):
    """
    This namespace is for interacting with the Functions window.
    """
    __open__ = staticmethod(idaapi.open_funcs_window)
    __open_defaults__ = (idaapi.BADADDR, )

class imports(appwindow):
    """
    This namespace is for interacting with the Imports window.
    """
    __open__ = staticmethod(idaapi.open_imports_window)
    __open_defaults__ = (idaapi.BADADDR, )

class libraries(appwindow):
    """
    This namespace is for interacting with the (Type) Libraries window.
    """
    __open__ = staticmethod(idaapi.open_tils_window)
    __open_defaults__ = (idaapi.BADADDR, )
tils = typelibraries = libraries

class modules(appwindow):
    """
    This namespace is for interacting with the Modules window.
    """
    __open__ = staticmethod(idaapi.open_modules_window)
    __open_defaults__ = (idaapi.BADADDR, )

class names(appwindow):
    """
    This namespace is for interacting with the Names window.
    """
    __open__ = staticmethod(idaapi.open_names_window)
    __open_defaults__ = (idaapi.BADADDR, )

    @classmethod
    def refresh(cls):
        '''Refresh the names list.'''
        return idaapi.refresh_lists() if idaapi.__version__ < 7.0 else idaapi.refresh_choosers()
    @classmethod
    def size(cls):
        '''Return the number of elements in the names list.'''
        return idaapi.get_nlist_size()
    @classmethod
    def contains(cls, ea):
        '''Return whether the address `ea` is referenced in the names list.'''
        return idaapi.is_in_nlist(ea)
    @classmethod
    def search(cls, ea):
        '''Return the index of the address `ea` in the names list.'''
        return idaapi.get_nlist_idx(ea)

    @classmethod
    def at(cls, index):
        '''Return the address and the symbol name of the specified `index`.'''
        ea, name = idaapi.get_nlist_ea(index), idaapi.get_nlist_name(index)
        return ea, internal.utils.string.of(name)
    @classmethod
    def name(cls, index):
        '''Return the name at the specified `index`.'''
        res = idaapi.get_nlist_name(index)
        return internal.utils.string.of(res)
    @classmethod
    def ea(cls, index):
        '''Return the address at the specified `index`.'''
        return idaapi.get_nlist_ea(index)

    @classmethod
    def iterate(cls):
        '''Iterate through all of the address and symbols in the names list.'''
        for idx in range(cls.size()):
            yield cls.at(idx)
        return

class notepad(appwindow):
    """
    This namespace is for interacting with the Notepad window.
    """
    __open__ = staticmethod(idaapi.open_notepad_window)
    __open_defaults__ = ()

    @classmethod
    def open(cls, *args):
        '''Open or show the notepad window and return its UI widget that can be used to modify it.'''
        widget = super(notepad, cls).open(*args)
        if isinstance(widget, PyQt5.QtWidgets.QPlainTextEdit):
            return widget

        elif hasattr(idaapi, 'is_idaq') and not idaapi.is_idaq():
            if not widget:
                raise internal.exceptions.UnsupportedCapability(u"{:s}.open({!s}) : Unable to open or interact with the notepad window when not running the Qt user-interface.".format('.'.join([__name__, cls.__name__]), ', '.join(map(internal.utils.string.repr, args))))
            return widget

        # We're running the PyQt UI, so we need to descend until we get to the text widget.
        children = (item for item in widget.children() if isinstance(item, PyQt5.QtWidgets.QPlainTextEdit))
        result = builtins.next(children, None)
        if result is None:
            raise internal.exceptions.ItemNotFoundError(u"{:s}.open({!s}) : Unable to locate the QtWidgets.QPlainTextEdit widget.".format('.'.join([__name__, cls.__name__]), ', '.join(map(internal.utils.string.repr, args))))
        return result

    @classmethod
    def close(cls):
        '''Close or hide the notepad window.'''
        editor = cls.open()
        widget = editor.parent()
        return widget.deleteLater()

    @classmethod
    def get(cls):
        '''Return the string that is currently stored within the notepad window.'''
        editor = cls.open()
        return editor.toPlainText()

    @classmethod
    def count(cls):
        '''Return the number of lines that are currently stored within the notepad window.'''
        editor = cls.open()
        result = editor.toPlainText()
        return result.count('\n') + (0 if result.endswith('\n') else 1)

    @classmethod
    def size(cls):
        '''Return the number of characters that are currently stored within the notepad window.'''
        editor = cls.open()
        result = editor.toPlainText()
        return len(result)

    @internal.utils.multicase(string=six.string_types)
    @classmethod
    def set(cls, string):
        '''Set the text that is currently stored within the notepad window to `string`.'''
        editor = cls.open()
        result, none = editor.toPlainText(), editor.setPlainText(string)
        return result

    @internal.utils.multicase(items=(builtins.list, builtins.tuple))
    @classmethod
    def set(cls, items):
        '''Set each line that is currently stored within the notepad window to `items`.'''
        return cls.set('\n'.join(items))

    @internal.utils.multicase(string=six.string_types)
    @classmethod
    def append(cls, string):
        '''Append the provided `string` to the current text that is stored within the notepad window.'''
        editor = cls.open()
        result, none = editor.toPlainText(), editor.appendPlainText(string)
        return result.count('\n') + (0 if result.endswith('\n') else 1)

    @internal.utils.multicase()
    @classmethod
    def cursor(cls):
        '''Return the ``QtGui.QTextCursor`` used by the notepad window.'''
        editor = cls.open()
        return editor.textCursor()

    @internal.utils.multicase()
    @classmethod
    def cursor(cls, cursor):
        '''Set the ``QtGui.QTextCursor`` for the notepad window to `cursor`.'''
        editor = cls.open()
        return editor.setTextCursor(cursor)

class problems(appwindow):
    """
    This namespace is for interacting with the Problems window.
    """
    __open__ = staticmethod(idaapi.open_problems_window)
    __open_defaults__ = (idaapi.BADADDR, )

class references(appwindow):
    """
    This namespace is for interacting with the Cross-References window.
    """
    __open__ = staticmethod(idaapi.open_xrefs_window)
    __open_defaults__ = (idaapi.BADADDR, )
xrefs = references

class segments(appwindow):
    """
    This namespace is for interacting with the Segments window.
    """
    __open__ = staticmethod(idaapi.open_segments_window)
    __open_defaults__ = (idaapi.BADADDR, )

class segmentregisters(appwindow):
    """
    This namespace is for interacting with the Segments window.
    """
    __open__ = staticmethod(idaapi.open_segments_window)
    __open_defaults__ = (idaapi.BADADDR, )
segregs = segmentregisters

class selectors(appwindow):
    """
    This namespace is for interacting with the Selectors window.
    """
    __open__ = staticmethod(idaapi.open_selectors_window)
    __open_defaults__ = (idaapi.BADADDR, )

class signatures(appwindow):
    """
    This namespace is for interacting with the Signatures window.
    """
    __open__ = staticmethod(idaapi.open_signatures_window)
    __open_defaults__ = (idaapi.BADADDR, )

class stack(appwindow):
    """
    This namespace is for interacting with the (Call) Stack window.
    """
    __open__ = staticmethod(idaapi.open_stack_window)
    __open_defaults__ = (idaapi.BADADDR, )
callstack = stack

class strings(appwindow):
    """
    This namespace is for interacting with the Strings window.
    """
    __open__ = staticmethod(idaapi.open_strings_window)
    __open_defaults__ = (idaapi.BADADDR, idaapi.BADADDR, idaapi.BADADDR)

    @classmethod
    def __on_openidb__(cls, code, is_old_database):
        if code != idaapi.NW_OPENIDB or is_old_database:
            raise internal.exceptions.InvalidParameterError(u"{:s}.__on_openidb__({:#x}, {:b}) : Hook was called with an unexpected code or an old database.".format('.'.join([__name__, cls.__name__]), code, is_old_database))
        config = idaapi.strwinsetup_t()
        config.minlen = 3
        config.ea1, config.ea2 = idaapi.cvar.inf.minEA, idaapi.cvar.inf.maxEA
        config.display_only_existing_strings = True
        config.only_7bit = True
        config.ignore_heads = False

        # aggregate all the string types for IDA 6.95x
        if idaapi.__version__ < 7.0:
            res = [idaapi.ASCSTR_TERMCHR, idaapi.ASCSTR_PASCAL, idaapi.ASCSTR_LEN2, idaapi.ASCSTR_UNICODE, idaapi.ASCSTR_LEN4, idaapi.ASCSTR_ULEN2, idaapi.ASCSTR_ULEN4]

        # otherwise use IDA 7.x's naming scheme
        else:
            res = [idaapi.STRTYPE_TERMCHR, idaapi.STRTYPE_PASCAL, idaapi.STRTYPE_LEN2, idaapi.STRTYPE_C_16, idaapi.STRTYPE_LEN4, idaapi.STRTYPE_LEN2_16, idaapi.STRTYPE_LEN4_16]

        config.strtypes = functools.reduce(lambda result, item: result | pow(2, item), res, 0)
        if not idaapi.set_strlist_options(config):
            raise internal.exceptions.DisassemblerError(u"{:s}.__on_openidb__({:#x}, {:b}) : Unable to set the default options for the string list.".format('.'.join([__name__, cls.__name__]), code, is_old_database))
        return
        #assert idaapi.build_strlist(config.ea1, config.ea2), "{:#x}:{:#x}".format(config.ea1, config.ea2)

    @classmethod
    def refresh(cls):
        '''Refresh the strings list.'''
        return idaapi.refresh_lists() if idaapi.__version__ < 7.0 else idaapi.refresh_choosers()
    @classmethod
    def size(cls):
        '''Return the number of items available in the strings list.'''
        return idaapi.get_strlist_qty()
    @classmethod
    def at(cls, index):
        '''Return the ``idaapi.string_info_t`` for the specified `index` in the strings list.'''
        si = idaapi.string_info_t()
        if not idaapi.get_strlist_item(si, index):
            raise internal.exceptions.DisassemblerError(u"{:s}.at({:d}) : The call to `idaapi.get_strlist_item({:d})` did not return successfully.".format('.'.join([__name__, cls.__name__]), index, index))
        return si
    @classmethod
    def get(cls, index):
        '''Return the address and its bytes representing the string at the specified `index`.'''
        si = cls.at(index)
        get_contents = idaapi.get_strlit_contents if hasattr(idaapi, 'get_strlit_contents') else idaapi.get_ascii_contents
        string = get_contents(si.ea, si.length, si.type)
        return si.ea, internal.utils.string.of(string)
    @classmethod
    def __iterate__(cls):
        '''Iterate through all of the items in the strings list yielding the `(index, address, bytes)`.'''
        for index in range(cls.size()):
            ea, item = cls.get(index)
            yield index, ea, item
        return
    @classmethod
    def iterate(cls):
        '''Iterate through all of the addresses and items in the strings list.'''
        for _, ea, item in cls.__iterate__():
            yield ea, item
        return

class structures(appwindow):
    """
    This namespace is for interacting with the Structures window.
    """
    __open__ = staticmethod(idaapi.open_structs_window)
    __open_defaults__ = (idaapi.BADADDR, 0)

class threads(appwindow):
    """
    This namespace is for interacting with the Threads window.
    """
    __open__ = staticmethod(idaapi.open_threads_window)
    __open_defaults__ = (idaapi.BADADDR, )

class tracing(appwindow):
    """
    This namespace is for interacting with the Tracing window.
    """
    __open__ = staticmethod(idaapi.open_trace_window)
    __open_defaults__ = (idaapi.BADADDR, )
trace = tracing

class types(appwindow):
    """
    This namespace is for interacting with the Types window.
    """
    __open__ = staticmethod(idaapi.open_loctypes_window)
    __open_defaults__ = (idaapi.BADADDR, )

class timer(object):
    """
    This namespace is for registering a python callable to a timer in IDA.
    """
    clock = {}
    @classmethod
    def register(cls, id, interval, callable):
        '''Register the specified `callable` with the requested `id` to be called at every `interval`.'''
        if id in cls.clock:
            idaapi.unregister_timer(cls.clock[id])

        # XXX: need to create a closure that can terminate when signalled
        cls.clock[id] = res = idaapi.register_timer(interval, callable)
        return res
    @classmethod
    def unregister(cls, id):
        '''Unregister the specified `id`.'''
        raise internal.exceptions.UnsupportedCapability(u"{:s}.unregister({!s}) : A lock or a signal is needed here in order to unregister this timer safely.".format('.'.join([__name__, cls.__name__]), id))
        idaapi.unregister_timer(cls.clock[id])
        del(cls.clock[id])
    @classmethod
    def reset(cls):
        '''Remove all the registered timers.'''
        for id, clk in cls.clock.items():
            idaapi.unregister_timer(clk)
            del(cls.clock[id])
        return

### updating the state of the colored navigation band
class navigation(object):
    """
    This namespace is for updating the state of the colored navigation band.
    """
    if all(not hasattr(idaapi, name) for name in ['show_addr', 'showAddr']):
        __set__ = staticmethod(lambda ea: None)
    else:
        __set__ = staticmethod(idaapi.showAddr if idaapi.__version__ < 7.0 else idaapi.show_addr)

    if all(not hasattr(idaapi, name) for name in ['show_auto', 'showAuto']):
        __auto__ = staticmethod(lambda ea, t: None)
    else:
        __auto__ = staticmethod(idaapi.showAuto if idaapi.__version__ < 7.0 else idaapi.show_auto)

    @classmethod
    def set(cls, ea):
        '''Set the auto-analysis address on the navigation bar to `ea`.'''
        result, _ = ea, cls.__set__(ea)
        return result

    @classmethod
    def auto(cls, ea, **type):
        """Set the auto-analysis address and type on the navigation bar to `ea`.

        If `type` is specified, then update using the specified auto-analysis type.
        """
        result, _ = ea, cls.__auto__(ea, type.get('type', idaapi.AU_NONE))
        return result

    @classmethod
    def unknown(cls, ea): return cls.auto(ea, type=idaapi.AU_UNK)
    @classmethod
    def code(cls, ea): return cls.auto(ea, type=idaapi.AU_CODE)
    @classmethod
    def weak(cls, ea): return cls.auto(ea, type=idaapi.AU_WEAK)
    @classmethod
    def procedure(cls, ea): return cls.auto(ea, type=idaapi.AU_PROC)
    @classmethod
    def tail(cls, ea): return cls.auto(ea, type=idaapi.AU_TAIL)
    @classmethod
    def stackpointer(cls, ea): return cls.auto(ea, type=idaapi.AU_TRSP)
    @classmethod
    def analyze(cls, ea): return cls.auto(ea, type=idaapi.AU_USED)
    @classmethod
    def type(cls, ea): return cls.auto(ea, type=idaapi.AU_TYPE)
    @classmethod
    def signature(cls, ea): return cls.auto(ea, type=idaapi.AU_LIBF)
    @classmethod
    def final(cls, ea): return cls.auto(ea, type=idaapi.AU_FINAL)

### interfacing with IDA's menu system
# FIXME: add some support for actually manipulating menus
class menu(object):
    """
    This namespace is for registering items in IDA's menu system.
    """
    state = {}
    @classmethod
    def add(cls, path, name, callable, hotkey='', flags=0, args=()):
        '''Register a `callable` as a menu item at the specified `path` with the provided `name`.'''

        # check to see if our menu item is in our cache and remove it if so
        if (path, name) in cls.state:
            cls.rm(path, name)

        # now we can add the menu item since everything is ok
        # XXX: I'm not sure if the path needs to be utf8 encoded or not
        res = internal.utils.string.to(name)
        ctx = idaapi.add_menu_item(path, res, hotkey, flags, callable, args)
        cls.state[path, name] = ctx
    @classmethod
    def rm(cls, path, name):
        '''Remove the menu item at the specified `path` with the provided `name`.'''
        res = cls.state[path, name]
        idaapi.del_menu_item(res)
        del cls.state[path, name]
    @classmethod
    def reset(cls):
        '''Remove all currently registered menu items.'''
        for path, name in cls.state.keys():
            cls.rm(path, name)
        return

### Qt wrappers and namespaces
class window(object):
    """
    This namespace is for interacting with a specific window.
    """
    def __new__(cls):
        '''Return the currently active window.'''
        # FIXME: should probably traverse the application windows to figure out the
        #        exact one that is in use so that we can cast it to a QWindow.
        return application.window()

    @internal.utils.multicase(xy=tuple)
    def at(cls, xy):
        '''Return the widget at the specified (`x`, `y`) coordinate within the `xy` tuple.'''
        x, y = xy
        return application.window(x, y)

class windows(object):
    """
    This namespace is for interacting with any or all of the windows for the application.
    """
    def __new__(cls):
        '''Return all of the top-level windows.'''
        return application.windows()

    @classmethod
    def refresh(cls):
        '''Refresh all of lists and choosers within the application.'''
        global disassembly
        ok = idaapi.refresh_lists() if idaapi.__version__ < 7.0 else idaapi.refresh_choosers()
        return ok and disassembly.refresh()
refresh = internal.utils.alias(windows.refresh, 'windows')

class widget(object):
    """
    This namespace is for interacting with any of the widgets
    associated with the native user-interface.
    """
    @internal.utils.multicase()
    def __new__(cls):
        '''Return the widget that is currently being used.'''
        return cls.of(current.widget())
    @internal.utils.multicase(xy=tuple)
    def __new__(cls, xy):
        '''Return the widget at the specified (`x`, `y`) coordinate within the `xy` tuple.'''
        res = x, y = xy
        return cls.at(res)
    @internal.utils.multicase(title=six.string_types)
    def __new__(cls, title):
        '''Return the widget that is using the specified `title`.'''
        return cls.by(title)

    @classmethod
    def at(cls, xy):
        '''Return the widget at the specified (`x`, `y`) coordinate within the `xy` tuple.'''
        res = x, y = xy
        global application
        q = application()
        return q.widgetAt(x, y)

    @classmethod
    def open(cls, widget, flags, **target):
        '''Open the `widget` using the specified ``idaapi.WOPN_`` flags.'''
        twidget = cls.form(widget) if cls.isinstance(widget) else widget
        ok = idaapi.display_widget(twidget, flags)
        # FIXME: rather than returning whether it succeeded or not, we should
        #        return what the widget was attached to in order to locate it.
        return ok
    @classmethod
    def close(cls, widget, flags):
        '''Close the `widget` using the specified ``idaapi.WCLS_`` flags.'''
        twidget = cls.form(widget) if cls.isinstance(widget) else widget
        ok = idaapi.close_widget(twidget, flags)
        # FIXME: rather than returning whether it succeeded or not, we should
        #        return what the widget was attached to before we closed it.
        return ok

    @classmethod
    def show(cls, widget):
        '''Display the specified `widget` without putting it in focus.'''
        twidget = cls.form(widget) if cls.isinstance(widget) else widget
        res, ok = idaapi.get_current_widget(), idaapi.activate_widget(twidget, False)
        return cls.of(res) if ok else None
    @classmethod
    def focus(cls, widget):
        '''Activate the specified `widget` and put it in focus.'''
        twidget = cls.form(widget) if cls.isinstance(widget) else widget
        res, ok = idaapi.get_current_widget(), idaapi.activate_widget(twidget, True)
        return cls.of(res) if ok else None

    @classmethod
    def type(cls, widget):
        '''Return the ``idaapi.twidget_type_t`` for the given `widget`.'''
        twidget = cls.form(widget) if cls.isinstance(widget) else widget
        return idaapi.get_widget_type(twidget)
    @classmethod
    def title(cls, widget):
        '''Return the window title for the given `widget`.'''
        twidget = cls.form(widget) if cls.isinstance(widget) else widget
        return idaapi.get_widget_title(twidget)

    @internal.utils.multicase(title=six.string_types)
    @classmethod
    @internal.utils.string.decorate_arguments('title')
    def by(cls, title):
        '''Return the widget associated with the given window `title`.'''
        res = idaapi.find_widget(internal.utils.string.to(title))
        if res is None:
            raise internal.exceptions.ItemNotFoundError(u"{:s}.by({!r}) : Unable to locate a widget with the specified title ({!r}).".format('.'.join([__name__, cls.__name__]), title, title))
        return cls.of(res)

    @classmethod
    def of(cls, form):
        '''Return the UI widget for the IDA `form` that is provided.'''
        if hasattr(idaapi, 'is_idaq') and not idaapi.is_idaq():
            return form
        raise internal.exceptions.MissingMethodError
    @classmethod
    def form(cls, widget):
        '''Return the IDA form for the UI `widget` that is provided.'''
        if hasattr(idaapi, 'is_idaq') and not idaapi.is_idaq():
            return widget
        raise internal.exceptions.MissingMethodError
    @classmethod
    def isinstance(cls, object):
        '''Return whether the given `object` is of the correct type for the UI.'''
        if hasattr(idaapi, 'is_idaq') and not idaapi.is_idaq():
            return True
        raise internal.exceptions.MissingMethodError

class clipboard(object):
    """
    This namespace is for interacting with the current clipboard state.
    """
    def __new__(cls):
        '''Return the current clipboard.'''
        global application
        clp = application()
        return clp.clipboard()

class mouse(object):
    """
    Base namespace for interacting with the mouse input.
    """
    @classmethod
    def buttons(cls):
        '''Return the current mouse buttons that are being clicked.'''
        global application
        q = application()
        return q.mouseButtons()

    @classmethod
    def position(cls):
        '''Return the current `(x, y)` position of the cursor.'''
        raise internal.exceptions.MissingMethodError

class keyboard(object):
    """
    Base namespace for interacting with the keyboard input.
    """
    @classmethod
    def modifiers(cls):
        '''Return the current keyboard modifiers that are being used.'''
        global application
        q = application()
        return q.keyboardModifiers()

    @classmethod
    def __of_key__(cls, key):
        '''Convert the normalized hotkey tuple in `key` into a format that IDA can comprehend.'''
        Separators = {'-', '+'}
        Modifiers = {'ctrl', 'shift', 'alt'}

        # Validate the type of our parameter
        if not isinstance(key, tuple):
            raise internal.exceptions.InvalidParameterError(u"{:s}.of_key({!r}) : A key combination of an invalid type was provided as a parameter.".format('.'.join([__name__, cls.__name__]), key))

        # Find a separator that we can use, and use it to join our tuple into a
        # string with each element capitalized. That way it looks good for the user.
        separator = next(item for item in Separators)
        modifiers, hotkey = key

        components = [item.capitalize() for item in modifiers] + [hotkey.capitalize()]
        return separator.join(components)

    @classmethod
    def __normalize_key__(cls, hotkey):
        '''Normalize the string `key` to a tuple that can be used to lookup keymappings.'''
        Separators = {'-', '+', '_'}
        Modifiers = {'ctrl', 'shift', 'alt'}

        # First check to see if we were given a tuple or list. If so, then we might
        # have been given a valid hotkey. However, we still need to validate this.
        # So, to do that we'll concatenate each component together back into a string
        # and then recurse so we can validate using the same logic.
        if isinstance(hotkey, (tuple, list, set)):
            try:
                # If we were mistakenly given a set, then we need to reformat it.
                if isinstance(hotkey, set):
                    raise ValueError

                modifiers, key = hotkey

                # If modifiers is not of the correct type, then still need to reformat.
                if not isinstance(modifiers, (tuple, list, set)):
                    raise ValueError

            # If the tuple we received was of an invalid format, then extract the
            # modifiers that we can from it, and try again.
            except ValueError:
                modifiers = tuple(item for item in hotkey if item.lower() in Modifiers)
                key = ''.join(item for item in hotkey if item.lower() not in Modifiers)

            # Grab a separator, and join all our components together with it.
            separator = next(item for item in Separators)
            components = [item for item in modifiers] + [key]
            return cls.__normalize_key__(separator.join(components))

        # Next we need to normalize the separator used throughout the string by
        # simply converting any characters we might consider a separator into
        # a null-byte so we can split on it.
        normalized = functools.reduce(lambda agg, item: agg.replace(item, '\0'), Separators, hotkey)

        # Now we can split the normalized string so we can convert it into a
        # set. We will then iterate through this set collecting all of our known
        # key modifiers. Anything left must be a single key, so we can then
        # validate the hotkey we were given.
        components = { item.lower() for item in normalized.split('\0') }

        modifiers = { item for item in components if item in Modifiers }
        key = components ^ modifiers

        # Now we need to verify that we were given just one key. If we were
        # given any more, then this isn't a valid hotkey combination and we need
        # to bitch about it.
        if len(key) != 1:
            raise internal.exceptions.InvalidParameterError(u"{:s}.normalize_key({!s}) : An invalid hotkey combination ({!s}) was provided as a parameter.".format('.'.join([__name__, cls.__name__]), internal.utils.string.repr(hotkey), internal.utils.string.repr(hotkey)))

        res = next(item for item in key)
        if len(res) != 1:
            raise internal.exceptions.InvalidParameterError(u"{:s}.normalize_key({!s}) : The hotkey combination {!s} contains the wrong number of keys ({:d}).".format('.'.join([__name__, cls.__name__]), internal.utils.string.repr(hotkey), internal.utils.string.repr(res), len(res)))

        # That was it. Now to do the actual normalization, we need to sort our
        # modifiers into a tuple, and return the single hotkey that we extracted.
        res, = key
        return tuple(sorted(modifiers)), res

    # Create a cache to store the hotkey context, and the callable that was mapped to it
    __cache__ = {}

    @classmethod
    def list(cls):
        '''Display the current list of keyboard combinations that are mapped along with the callable each one is attached to.'''
        maxkey, maxtype, maxinfo = 0, 0, 0

        results = []
        for mapping, (capsule, closure) in cls.__cache__.items():
            key = cls.__of_key__(mapping)

            # Check if we were passed a class so we can figure out how to
            # extract the signature.
            cons = ['__init__', '__new__']
            if inspect.isclass(closure):
                available = (item for item in cons if hasattr(closure, item))
                attribute = next((item for item in available if inspect.ismethod(getattr(closure, item))), None)
                callable = getattr(closure, attribute) if attribute else None
                information = '.'.join([closure.__name__, internal.utils.multicase.prototype(callable)]) if attribute else "{:s}(...)".format(closure.__name__)
            else:
                information = internal.utils.multicase.prototype(closure)

            # Figure out the type of the callable that is mapped.
            if inspect.isclass(closure):
                ftype = 'class'
            elif inspect.ismethod(closure):
                ftype = 'method'
            elif inspect.isbuiltin(closure):
                ftype = 'builtin'
            elif inspect.isfunction(closure):
                ftype = 'anonymous' if closure.__name__ in {'<lambda>'} else 'function'
            else:
                ftype = 'callable'

            # Figure out if there's any class-information associated with the closure
            if inspect.ismethod(closure):
                klass = closure.im_self.__class__ if closure.im_self else closure.im_class
                clsinfo = klass.__name__ if getattr(klass, '__module__', '__main__') in {'__main__'} else '.'.join([klass.__module__, klass.__name__])
            elif inspect.isclass(closure) or isinstance(closure, object):
                clsinfo = '' if getattr(closure, '__module__', '__main__') in {'__main__'} else closure.__module__
            else:
                clsinfo = None if getattr(closure, '__module__', '__main__') in {'__main__'} else closure.__module__

            # Now we can figure out the documentation for the closure that was stored.
            documentation = closure.__doc__ or ''
            if documentation:
                filtered = [item.strip() for item in documentation.split('\n') if item.strip()]
                header = next((item for item in filtered), '')
                comment = "{:s}...".format(header) if header and len(filtered) > 1 else header
            else:
                comment = ''

            # Calculate our maximum column widths inline
            maxkey = max(maxkey, len(key))
            maxinfo = max(maxinfo, len('.'.join([clsinfo, information]) if clsinfo else information))
            maxtype = max(maxtype, len(ftype))

            # Append each column to our results
            results.append((key, ftype, clsinfo, information, comment))

        # If we didn't aggregate any results, then raise an exception as there's nothing to do.
        if not results:
            raise internal.exceptions.SearchResultsError(u"{:s}.list() : Found 0 key combinations mapped.".format('.'.join([__name__, cls.__name__])))

        # Now we can output what was mapped to the user.
        six.print_(u"Found the following{:s} key combination{:s}:".format(" {:d}".format(len(results)) if len(results) > 1 else '', '' if len(results) == 1 else 's'))
        for key, ftype, clsinfo, info, comment in results:
            six.print_(u"Key: {:>{:d}s} -> {:<{:d}s}{:s}".format(key, maxkey, "{:s}:{:s}".format(ftype, '.'.join([clsinfo, info]) if clsinfo else info), maxtype + 1 + maxinfo, " // {:s}".format(comment) if comment else ''))
        return

    @classmethod
    def map(cls, key, callable):
        """Map the specified `key` combination to a python `callable` in IDA.

        If the provided `key` is being re-mapped due to the mapping already existing, then return the previous callable that it was assigned to.
        """

        # First we'll normalize the hotkey that we were given, and convert it
        # back into a format that IDA can understand. This way we can prevent
        # users from giving us a sloppy hotkey combination that we won't be
        # able to search for in our cache.
        hotkey = cls.__normalize_key__(key)
        keystring = cls.__of_key__(hotkey)

        # The hotkey we normalized is now a tuple, so check to see if it's
        # already within our cache. If it is, then we need to unmap it prior to
        # re-creating the mapping.
        if hotkey in cls.__cache__:
            logging.warning(u"{:s}.map({!s}, {!r}) : Remapping the hotkey combination {!s} with the callable {!r}.".format('.'.join([__name__, cls.__name__]), internal.utils.string.repr(key), callable, internal.utils.string.repr(keystring), callable))
            ctx, _ = cls.__cache__[hotkey]

            ok = idaapi.del_hotkey(ctx)
            if not ok:
                raise internal.exceptions.DisassemblerError(u"{:s}.map({!s}, {!r}) : Unable to remove the hotkey combination {!s} from the list of current keyboard mappings.".format('.'.join([__name__, cls.__name__]), internal.utils.string.repr(key), callable, internal.utils.string.repr(keystring)))

            # Pop the callable that was mapped out of the cache so that we can
            # return it to the user.
            _, res = cls.__cache__.pop(hotkey)

        # If the user is mapping a new key, then there's no callable to return.
        else:
            res = None

        # Verify that the user gave us a callable to use to avoid mapping a
        # useless type to the specified keyboard combination.
        if not builtins.callable(callable):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.map({!s}, {!r}) : Unable to map the non-callable value {!r} to the hotkey combination {!s}.".format('.'.join([__name__, cls.__name__]), internal.utils.string.repr(key), callable, callable, internal.utils.string.repr(keystring)))

        # Define a closure that calls the user's callable as it seems that IDA's
        # hotkey functionality doesn't deal too well when the same callable is
        # mapped to different hotkeys.
        def closure(*args, **kwargs):
            return callable(*args, **kwargs)

        # Now we can add the hotkey to IDA using the closure that we generated.
        # XXX: I'm not sure if the key needs to be utf8 encoded or not
        ctx = idaapi.add_hotkey(keystring, closure)
        if not ctx:
            raise internal.exceptions.DisassemblerError(u"{:s}.map({!s}, {!r}) : Unable to map the callable {!r} to the hotkey combination {!s}.".format('.'.join([__name__, cls.__name__]), internal.utils.string.repr(key), callable, callable, internal.utils.string.repr(keystring)))

        # Last thing to do is to stash it in our cache with the user's callable
        # in order to keep track of it for removal.
        cls.__cache__[hotkey] = ctx, callable
        return res

    @classmethod
    def unmap(cls, key):
        '''Unmap the specified `key` from IDA and return the callable that it was assigned to.'''
        frepr = lambda hotkey: internal.utils.string.repr(cls.__of_key__(hotkey))

        # First check to see whether we were given a callable or a hotkey. If
        # we were given a callable, then we need to look through our cache for
        # the actual key that it was. Once found, then we normalize it like usual.
        if callable(key):
            try:
                hotkey = cls.__normalize_key__(next(item for item, (_, fcallback) in cls.__cache__.items() if fcallback == key))

            except StopIteration:
                raise internal.exceptions.InvalidParameterError(u"{:s}.unmap({:s}) : Unable to locate the callable {!r} in the current list of keyboard mappings.".format('.'.join([__name__, cls.__name__]), "{!r}".format(key) if callable(key) else "{!s}".format(internal.utils.string.repr(key)), key))

            else:
                logging.warning(u"{:s}.unmap({:s}) : Discovered the hotkey {!s} being currently mapped to the callable {!r}.".format('.'.join([__name__, cls.__name__]), "{!r}".format(key) if callable(key) else "{!s}".format(internal.utils.string.repr(key)), frepr(hotkey), key))

        # We need to normalize the hotkey we were given, and convert it back
        # into IDA's format. This way we can locate it in our cache, and prevent
        # sloppy user input from interfering.
        else:
            hotkey = cls.__normalize_key__(key)

        # Check to see if the hotkey is cached and warn the user if it isn't.
        if hotkey not in cls.__cache__:
            logging.warning(u"{:s}.unmap({:s}) : Refusing to unmap the hotkey {!s} as it is not currently mapped to anything.".format('.'.join([__name__, cls.__name__]), "{!r}".format(key) if callable(key) else "{!s}".format(internal.utils.string.repr(key)), frepr(hotkey)))
            return

        # Grab the keymapping context from our cache, and then ask IDA to remove
        # it for us. If we weren't successful, then raise an exception so the
        # user knows what's up.
        ctx, _ = cls.__cache__[hotkey]
        ok = idaapi.del_hotkey(ctx)
        if not ok:
            raise internal.exceptions.DisassemblerError(u"{:s}.unmap({:s}) : Unable to unmap the specified hotkey ({!s}) from the current list of keyboard mappings.".format('.'.join([__name__, cls.__name__]), "{!r}".format(key) if callable(key) else "{!s}".format(internal.utils.string.repr(key)), frepr(hotkey)))

        # Now we can pop off the callable that was mapped to the hotkey context
        # in order to return it, and remove the hotkey from our cache.
        _, res = cls.__cache__.pop(hotkey)
        return res

    add, rm = internal.utils.alias(map, 'keyboard'), internal.utils.alias(unmap, 'keyboard')

    @classmethod
    def input(cls):
        '''Return the current keyboard input context.'''
        raise internal.exceptions.MissingMethodError

### PyQt5-specific functions and namespaces
## these can overwrite any of the classes defined above
try:
    import PyQt5.Qt
    from PyQt5.Qt import QObject, QWidget

    class application(application):
        """
        This namespace is for getting information about the application user-interface
        that is based on PyQt.
        """
        def __new__(cls):
            '''Return the current instance of the PyQt Application.'''
            q = PyQt5.Qt.qApp
            return q.instance()

        @internal.utils.multicase()
        @classmethod
        def window(cls):
            '''Return the active main window for the PyQt application.'''
            q = cls()
            widgets = q.topLevelWidgets()
            return next(widget for widget in widgets if isinstance(widget, PyQt5.QtWidgets.QMainWindow))
        @internal.utils.multicase(x=six.integer_types, y=six.integer_types)
        @classmethod
        def window(cls, x, y):
            '''Return the window at the specified `x` and `y` coordinate.'''
            q = cls()
            return q.topLevelAt(x, y)

        @classmethod
        def windows(cls):
            '''Return all of the available windows for the application.'''
            q = cls()
            return q.topLevelWindows()

    class mouse(mouse):
        """
        This namespace is for interacting with the mouse input.
        """
        @classmethod
        def position(cls):
            '''Return the current `(x, y)` position of the cursor.'''
            qt = PyQt5.QtGui.QCursor
            res = qt.pos()
            return res.x(), res.y()

    class keyboard(keyboard):
        """
        This namespace is for interacting with the keyboard input.
        """
        @classmethod
        def input(cls):
            '''Return the current keyboard input context.'''
            raise internal.exceptions.MissingMethodError

    class UIProgress(object):
        """
        Helper class used to simplify the showing of a progress bar in IDA's UI.
        """
        timeout = 5.0

        def __init__(self, blocking=True):
            self.object = res = PyQt5.Qt.QProgressDialog()
            res.setVisible(False)
            res.setWindowModality(blocking)
            res.setAutoClose(True)

            self.__evrunning = event = threading.Event()
            res.canceled.connect(event.set)

            pwd = _database.config.path() or os.getcwd()
            path = os.path.join(pwd, _database.config.filename()) if _database.config.filename() else pwd

            self.update(current=0, min=0, max=0, text=u'Processing...', tooltip=u'...', title=path)

        # properties
        canceled = property(fget=lambda self: self.object.wasCanceled(), fset=lambda self, value: self.object.canceled.connect(value))
        maximum = property(fget=lambda self: self.object.maximum())
        minimum = property(fget=lambda self: self.object.minimum())
        current = property(fget=lambda self: self.object.value())

        @property
        def canceled(self):
            return self.__evrunning.is_set()
        @canceled.setter
        def canceled(self, set):
            event = self.__evrunning
            event.set() if set else event.clear()

        # methods
        def open(self, width=0.8, height=0.1):
            '''Open a progress bar with the specified `width` and `height` relative to the dimensions of IDA's window.'''
            cls, app = self.__class__, application()

            # XXX: spin for a second until main is defined because IDA seems to be racy with this api
            ts, main = time.time(), getattr(self, '__appwindow__', None)
            while time.time() - ts < self.timeout and main is None:
                _, main = app.processEvents(), application.window()

            if main is None:
                logging.warning(u"{:s}.open({!s}, {!s}) : Unable to find main application window. Falling back to default screen dimensions to calculate size.".format('.'.join([__name__, cls.__name__]), width, height))

            # figure out the dimensions of the window
            if main is None:
                # if there's no window, then assume some screen dimensions
                w, h = 1024, 768
            else:
                w, h = main.width(), main.height()

            # now we can calculate the dimensions of the progress bar
            logging.info(u"{:s}.open({!s}, {!s}) : Using dimensions ({:d}, {:d}) for progress bar.".format('.'.join([__name__, cls.__name__]), width, height, int(w*width), int(h*height)))
            fixedWidth, fixedHeight = map(math.trunc, [w * width, h * height])
            self.object.setFixedWidth(fixedWidth), self.object.setFixedHeight(fixedHeight)

            # calculate the center
            if main is None:
                # no window, so use the center of the screen
                cx, cy = w * 0.5, h * 0.5
            else:
                center = main.geometry().center()
                cx, cy = center.x(), center.y()

            # ...and center it.
            x, y = map(math.trunc, [cx - (w * width * 0.5), cy - (h * height * 1.0)])
            logging.info(u"{:s}.open({!s}, {!s}) : Centering progress bar at ({:d}, {:d}).".format('.'.join([__name__, cls.__name__]), width, height, int(x), int(y)))
            self.object.move(x, y)

            # now everything should look good.
            self.object.show(), app.processEvents()

        def close(self):
            '''Close the current progress bar.'''
            event, app = self.__evrunning, application()
            self.object.canceled.disconnect(event.set)
            self.object.close(), app.processEvents()

        def update(self, **options):
            '''Update the current state of the progress bar.'''
            application().processEvents()

            minimum, maximum = options.get('min', None), options.get('max', None)
            text, title, tooltip = (options.get(item, None) for item in ['text', 'title', 'tooltip'])

            if minimum is not None:
                self.object.setMinimum(minimum)
            if maximum is not None:
                self.object.setMaximum(maximum)
            if title is not None:
                self.object.setWindowTitle(internal.utils.string.to(title))
            if tooltip is not None:
                self.object.setToolTip(internal.utils.string.to(tooltip))
            if text is not None:
                self.object.setLabelText(internal.utils.string.to(text))

            res = self.object.value()
            if 'current' in options:
                self.object.setValue(options['current'])
            elif 'value' in options:
                self.object.setValue(options['value'])
            return res

    if hasattr(idaapi, 'is_idaq') and not idaapi.is_idaq():
        raise StopIteration

    class widget(widget):
        """
        This namespace is for interacting with any of the widgets
        associated with the native PyQT5 user-interface.
        """
        __cache__ = {}
        @classmethod
        def of(cls, form):
            '''Return the PyQt widget for the IDA `form` that is provided.'''
            ns = idaapi.PluginForm
            iterable = (getattr(ns, attribute) for attribute in ['TWidgetToPyQtWidget', 'FormToPyQtWidget'] if hasattr(ns, attribute))
            F = next(iterable, None)
            if F is None:
                raise internal.exceptions.UnsupportedVersion(u"{:s}.of({!s}) : Unable to return the PyQT widget from a plugin form due to it being unsupported by the current version of IDA.".format('.'.join([__name__, cls.__name__]), form))
            result = F(form)
            cls.__cache__[result] = form
            return result
        @classmethod
        def form(cls, widget):
            '''Return the IDA form for the PyQt `widget` that is provided.'''
            ns = idaapi.PluginForm
            if hasattr(ns, 'QtWidgetToTWidget'):
                return ns.QtWidgetToTWidget(widget)
            elif widget in cls.__cache__:
                return cls.__cache__[widget]
            raise internal.exceptions.UnsupportedVersion(u"{:s}.of({!s}) : Unable to return the plugin form from a PyQT widget due to it being unsupported by the current version of IDA.".format('.'.join([__name__, cls.__name__]), widget))
        @classmethod
        def isinstance(cls, widget):
            '''Return whether the given `object` is a PyQt widget.'''
            return isinstance(widget, QWidget)

except StopIteration:
    pass

except ImportError:
    logging.info(u"{:s}:Unable to locate `PyQt5.Qt` module.".format(__name__))

### PySide-specific functions and namespaces
try:
    import PySide
    import PySide.QtCore, PySide.QtGui

    class application(application):
        """
        This namespace is for getting information about the application user-interface
        that is based on PySide.
        """
        def __new__(cls):
            '''Return the current PySide instance of the application.'''
            res = PySide.QtCore.QCoreApplication
            return res.instance()

        @internal.utils.multicase()
        @classmethod
        def window(cls):
            '''Return the active main window for the PySide application.'''

            # Apparently PySide.QtCore.QCoreApplication is actually considered
            # the main window for the application. Go figure...
            return cls()
        @internal.utils.multicase(x=six.integer_types, y=six.integer_types)
        @classmethod
        def window(cls, x, y):
            '''Return the window at the specified `x` and `y` coordinate.'''
            q = cls()
            return q.topLevelAt(x, y)

        @classmethod
        def windows(cls):
            '''Return all of the available windows for the application.'''
            app = cls()
            items = app.topLevelWidgets()
            return [item for item in items if top.isWindow()]

    class mouse(mouse):
        """
        This namespace is for interacting with the mouse input.
        """
        @classmethod
        def position(cls):
            '''Return the current `(x, y)` position of the cursor.'''
            qt = PySide.QtGui.QCursor
            res = qt.pos()
            return res.x(), res.y()

    class keyboard(keyboard):
        """
        PySide keyboard interface.
        """
        @classmethod
        def input(cls):
            '''Return the current keyboard input context.'''
            return q.inputContext()

    if hasattr(idaapi, 'is_idaq') and not idaapi.is_idaq():
        raise StopIteration

    class widget(widget):
        """
        This namespace is for interacting with any of the widgets
        associated with the native PySide user-interface.
        """
        __cache__ = {}
        @classmethod
        def of(cls, form):
            '''Return the PySide widget for the IDA `form` that is provided.'''
            ns = idaapi.PluginForm
            iterable = (getattr(ns, attribute) for attribute in ['TWidgetToPySideWidget', 'FormToPySideWidget'] if hasattr(ns, attribute))
            F = next(iterable, None)
            if F is None:
                raise internal.exceptions.UnsupportedVersion(u"{:s}.of({!s}) : Unable to return the PySide widget from a plugin form due to it being unsupported by the current version of IDA.".format('.'.join([__name__, cls.__name__]), form))
            result = F(form)
            cls.__cache__[result] = form
            return result

        @classmethod
        def form(cls, widget):
            '''Return the IDA form for the PySide `widget` that is provided.'''
            if widget in cls.__cache__:
                return cls.__cache__[widget]
            raise internal.exceptions.UnsupportedCapability(u"{:s}.of({!s}) : Unable to return the plugin form from a PySide widget due to it being unsupported by the current version of IDA.".format('.'.join([__name__, cls.__name__]), widget))

        @classmethod
        def isinstance(cls, object):
            '''Return whether the given `object` is a PySide widget.'''
            return isinstance(object, PySide.QtCore.QObject)

except StopIteration:
    pass

except ImportError:
    logging.info(u"{:s}:Unable to locate `PySide` module.".format(__name__))

### wrapper that uses a priorityhook around IDA's hooking capabilities.
class hook(object):
    """
    This namespace exposes the ability to hook different parts of IDA.

    There are 4 different event types in IDA that can be hooked. These
    are available under the ``hook.idp``, ``hook.idb``, ``hook.ui``,
    and ``hook.notification`` objects.

    To add a hook for any of these event types, one can use
    the `add(target, callable, priority)` method to associate a python
    callable with the desired event. After the callable has been
    attached, the `enable(target)` or `disable(target)` methods can be
    used to temporarily enable or disable the hook.

    Please refer to the documentation for the ``idaapi.IDP_Hooks``,
    ``idaapi.IDB_Hooks``, and ``idaapi.UI_Hooks`` classes for
    identifying what event targets are available to hook. Similarly,
    the documentation for ``idaapi.notify_when`` can be used to list
    the targets available for notification hooks.
    """

    @classmethod
    def __start_ida__(ns):
        import hooks

        # Create an alias to save some typing and a table of the attribute
        # name, the base hook class, and the supermethods we need to patch.
        priorityhook, api = internal.interface.priorityhook, {
            'idp':  (idaapi.IDP_Hooks,  hooks.supermethods.IDP_Hooks.mapping),
            'idb':  (idaapi.IDB_Hooks,  hooks.supermethods.IDB_Hooks.mapping),
            'ui':   (idaapi.UI_Hooks,   hooks.supermethods.UI_Hooks.mapping),
        }

        # Iterate through our table and use it to instantiate the necessary
        # objects for each hook type whilst attaching the patched supermethods.
        for attribute, (klass, supermethods) in api.items():

            # If there's an instance already attached to us, then use it.
            if hasattr(ns, attribute):
                instance = getattr(ns, attribute)

            # Otherwise instantiate the priority hooks for each hook type,
            # and assign it directly into our class. We attach a supermethod
            # mapping to patch the original supermethods of each hook where
            # it can either have a completely different number of parameters
            # or different types than what is listed within the documentation.
            else:
                instance = priorityhook(klass, supermethods)
                setattr(ns, attribute, instance)

            # Log some information about what we've just done.
            logging.info(u"{:s} : Attached an instance of `{:s}` to `{:s}` which is now available at `{:s}`.".format('.'.join([__name__, ns.__name__]), instance.__class__.__name__, klass.__name__, '.'.join([__name__, ns.__name__, attribute])))

        # If the idaapi.__notification__ object exists, then also
        # assign it directly into our namespace.
        if not hasattr(ns, 'notification') and hasattr(idaapi, '__notification__'):
            instance = idaapi.__notification__
            setattr(ns, 'notification', instance)
            logging.info(u"{:s} : Attached an instance of `{:s}` to {:s} which is now accessible at `{:s}`.".format('.'.join([__name__, ns.__name__]), instance.__class__.__name__, 'notifications', '.'.join([__name__, ns.__name__, 'notification'])))
        return

    @classmethod
    def __stop_ida__(ns):
        for api in ['idp', 'idb', 'ui']:

            # grab the individual class that was used to hook things
            instance = getattr(ns, api)

            # and then unhook it completely, because IDA on linux
            # seems to still dispatch to those hooks...even when
            # the language extension is unloaded.
            instance.close()
        return

    # if there's a __notification__ attribute attached to IDA, then
    # assign it to our namespace so it can be used.
    if hasattr(idaapi, '__notification__'):
        notification = idaapi.__notification__

hooks = hook    # XXX: ns alias

### Helper classes to use or inherit from
# XXX: why was this base class implemented again??
class InputBox(idaapi.PluginForm):
    """
    A class designed to be inherited from that can be used
    to interact with the user.
    """
    def OnCreate(self, form):
        '''A method to overload to be notified when the plugin form is created.'''
        self.parent = self.FormToPyQtWidget(form)

    def OnClose(self, form):
        '''A method to overload to be notified when the plugin form is destroyed.'''
        pass

    def Show(self, caption, options=0):
        '''Show the form with the specified `caption` and `options`.'''
        res = internal.utils.string.to(caption)
        return super(InputBox, self).Show(res, options)

### Console-only progress bar
class ConsoleProgress(object):
    """
    Helper class used to simplify the showing of a progress bar in IDA's console.
    """
    def __init__(self, blocking=True):
        self.__path__ = os.path.join(_database.config.path(), _database.config.filename())
        self.__value__ = 0
        self.__min__, self.__max__ = 0, 0
        return

    canceled = property(fget=operator.not_, fset=operator.eq)
    maximum = property(fget=lambda self: self.__max__)
    minimum = property(fget=lambda self: self.__min__)
    current = property(fget=lambda self: self.__value__)

    def open(self, width=0.8, height=0.1):
        '''Open a progress bar with the specified `width` and `height` relative to the dimensions of IDA's window.'''
        return

    def close(self):
        '''Close the current progress bar.'''
        return

    def update(self, **options):
        '''Update the current state of the progress bar.'''
        minimum, maximum = options.get('min', None), options.get('max', None)
        text, title, tooltip = (options.get(item, None) for item in ['text', 'title', 'tooltip'])

        if minimum is not None:
            self.__min__ = minimum
        if maximum is not None:
            self.__max__ = maximum

        res = self.__value__
        if 'current' in options:
            self.__value__ = options['current']
        if 'value' in options:
            self.__value__ = options['value']

        if text is not None:
            six.print_(internal.utils.string.of(text))

        return res

### Fake progress bar class that instantiates whichever one is available
class Progress(object):
    """
    The default progress bar in with which to show progress. This class will
    automatically determine which progress bar (Console or UI) to instantiate
    based on what is presently available.
    """

    timeout = 5.0

    def __new__(cls, *args, **kwargs):
        '''Figure out which progress bar to use and instantiate it with the provided parameters `args` and `kwargs`.'''
        if not all([idaapi.is_idaq(), 'UIProgress' in globals()]):
            logging.warning(u"{:s}(...) : Using console-only implementation of the `ui.Progress` class.".format('.'.join([__name__, cls.__name__])))
            return ConsoleProgress(*args, **kwargs)

        # XXX: spin for a bit looking for the application window as IDA seems to be racy with this for some reason
        ts, main = time.time(), getattr(cls, '__appwindow__', None)
        while time.time() - ts < cls.timeout and main is None:
            main = application.window()

        # If no main window was found, then fall back to the console-only progress bar
        if main is None:
            logging.warning(u"{:s}(...) : Unable to find main application window. Falling back to console-only implementation of the `ui.Progress` class.".format('.'.join([__name__, cls.__name__])))
            return ConsoleProgress(*args, **kwargs)

        cls.__appwindow__ = main
        return UIProgress(*args, **kwargs)
