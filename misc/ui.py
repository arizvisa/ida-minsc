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

import six
import sys, os, time
import logging

import idaapi, internal
import database as _database

## TODO:
# locate window under current cursor position
# pop-up a menu item
# pop-up a form/messagebox
# another item menu to toolbar
# find the QAction associated with a command (or keypress)

def application():
    '''Return the current instance of the IDA Application.'''
    raise internal.exceptions.MissingMethodError

@document.parameters(string='the string to ask the user', default='if ``yes``, ``no``, or ``cancel`` is set to true, then use that value as the default')
def ask(string, **default):
    """Ask the user a question providing the option to choose "yes", "no", or "cancel".

    If any of the options are specified as a boolean, then it is
    assumed that this option will be the default. If the user
    chooses "cancel", then this value will be returned instead of
    the value ``None``.
    """
    state = {'no': 0, 'yes': 1, 'cancel': -1}
    results = {0: False, 1: True}
    if default:
        keys = {n for n in default.viewkeys()}
        keys = {n.lower() for n in keys if default.get(n, False)}
        dflt = next((k for k in keys), 'cancel')
    else:
        dflt = 'cancel'
    res = idaapi.ask_yn(state[dflt], internal.utils.string.to(string))
    return results.get(res, None)

@document.namespace
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
            raise internal.exceptions.FunctionNotFoundError(u"{:s}.function() : Unable to locate the current function.".format('.'.join((__name__, cls.__name__))))
        return res
    @classmethod
    def segment(cls):
        '''Return the current segment.'''
        ea = cls.address()
        return idaapi.getseg(ea)
    @classmethod
    def status(cls):
        '''Return the IDA status.'''
        raise internal.exceptions.UnsupportedCapability(u"{:s}.status() : Unable to return the current status of IDA.".format('.'.join((__name__, cls.__name__))))
    @classmethod
    def symbol(cls):
        '''Return the current highlighted symbol name.'''
        return idaapi.get_highlighted_identifier()
    @document.aliases('current.selected')
    @classmethod
    def selection(cls):
        '''Return the current address range of whatever is selected'''
        view = idaapi.get_current_viewer()
        left, right = idaapi.twinpos_t(), idaapi.twinpos_t()
        ok = idaapi.read_selection(view, left, right)
        if not ok:
            raise internal.exceptions.DisassemblerError(u"{:s}.selection() : Unable to read the current selection.".format('.'.join((__name__, cls.__name__))))
        pl_l, pl_r = left.place(view), right.place(view)
        ea_l, ea_r = internal.interface.address.inside(pl_l.ea, pl_r.ea)
        return internal.interface.bounds_t(ea_l, ea_r)
    selected = internal.utils.alias(selection, 'current')
    @classmethod
    def opnum(cls):
        '''Return the currently selected operand number.'''
        return idaapi.get_opnum()
    @classmethod
    def widget(cls):
        '''Return the current widget that the mouse is hovering over.'''
        # XXX: there's probably a better way to do this rather than looking
        #      at the mouse cursor position
        x, y = mouse.position()
        return widget.at((x, y))
    @classmethod
    def window(cls):
        '''Return the current window that is being used.'''
        global window
        # FIXME: cast this to a QWindow somehow?
        return window.main()

@document.namespace
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

    @document.aliases('wait')
    @classmethod
    def wait(cls):
        '''Wait until IDA's autoanalysis queues are empty.'''
        return idaapi.autoWait() if idaapi.__version__ < 7.0 else idaapi.auto_wait()

    @document.aliases('beep')
    @classmethod
    def beep(cls):
        '''Beep using IDA's interface.'''
        return idaapi.beep()

    @document.aliases('refresh')
    @classmethod
    def refresh(cls):
        '''Refresh all of IDA's windows.'''
        global disassembly
        idaapi.refresh_lists()
        disassembly.refresh()

wait, beep, refresh = internal.utils.alias(state.wait, 'state'), internal.utils.alias(state.beep, 'state'), internal.utils.alias(state.refresh, 'state')

@document.namespace
class appwindow(object):
    """
    Base namespace used for interacting with the windows provided by IDA.
    """
    @classmethod
    @document.parameters(args='any options or arguments to pass to the windows open function')
    def open(cls, *args):
        '''Open or show the window belonging to the namespace.'''
        global widget
        res = cls.__open__(*args) if args else cls.__open__(*getattr(cls, '__open_defaults__', ()))
        return widget.form(res)

    @classmethod
    def close(cls):
        '''Close or hide the window belonging to the namespace.'''
        res = cls.open()
        return res.deleteLater()

@document.namespace
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

@document.namespace
class exports(appwindow):
    """
    This namespace is for interacting with the Exports window.
    """
    __open__ = staticmethod(idaapi.open_exports_window)
    __open_defaults__ = (idaapi.BADADDR, )

@document.namespace
class imports(appwindow):
    """
    This namespace is for interacting with the Imports window.
    """
    __open__ = staticmethod(idaapi.open_imports_window)
    __open_defaults__ = (idaapi.BADADDR, )

@document.namespace
class names(appwindow):
    """
    This namespace is for interacting with the Names window.
    """
    __open__ = staticmethod(idaapi.open_names_window)
    __open_defaults__ = (idaapi.BADADDR, )

    @classmethod
    def refresh(cls):
        '''Refresh the names list.'''
        return idaapi.refresh_lists()
    @classmethod
    def size(cls):
        '''Return the number of elements in the names list.'''
        return idaapi.get_nlist_size()
    @classmethod
    @document.parameters(ea='the address of the symbol to check')
    def contains(cls, ea):
        '''Return whether the address `ea` is referenced in the names list.'''
        return idaapi.is_in_nlist(ea)
    @classmethod
    @document.parameters(ea='the address of the symbol to return the index for')
    def search(cls, ea):
        '''Return the index of the address `ea` in the names list.'''
        return idaapi.get_nlist_idx(ea)

    @classmethod
    @document.parameters(index='the index in the list to return')
    def at(cls, index):
        '''Return the address and the symbol name of the specified `index`.'''
        ea, name = idaapi.get_nlist_ea(index), idaapi.get_nlist_name(index)
        return ea, internal.utils.string.of(name)
    @classmethod
    @document.parameters(index='the index in the list to return')
    def name(cls, index):
        '''Return the name at the specified `index`.'''
        res = idaapi.get_nlist_name(index)
        return internal.utils.string.of(res)
    @classmethod
    @document.parameters(index='the index in the list to return')
    def ea(cls, index):
        '''Return the address at the specified `index`.'''
        return idaapi.get_nlist_ea(index)

    @classmethod
    def iterate(cls):
        '''Iterate through all of the address and symbols in the names list.'''
        for idx in six.moves.range(cls.size()):
            yield cls.at(idx)
        return

@document.namespace
class functions(appwindow):
    """
    This namespace is for interacting with the Functions window.
    """
    __open__ = staticmethod(idaapi.open_funcs_window)
    __open_defaults__ = (idaapi.BADADDR, )

@document.namespace
class structures(appwindow):
    """
    This namespace is for interacting with the Structures window.
    """
    __open__ = staticmethod(idaapi.open_structs_window)
    __open_defaults__ = (idaapi.BADADDR, 0)

@document.namespace
class strings(appwindow):
    """
    This namespace is for interacting with the Strings window.
    """
    __open__ = staticmethod(idaapi.open_strings_window)
    __open_defaults__ = (idaapi.BADADDR, idaapi.BADADDR, idaapi.BADADDR)

    @classmethod
    def __on_openidb__(cls, code, is_old_database):
        if code != idaapi.NW_OPENIDB or is_old_database:
            raise internal.exceptions.InvalidParameterError(u"{:s}.__on_openidb__({:#x}, {:b}) : Hook was called with an unexpected code or an old database.".format('.'.join((__name__, cls.__name__)), code, is_old_database))
        config = idaapi.strwinsetup_t()
        config.minlen = 3
        config.ea1, config.ea2 = idaapi.cvar.inf.minEA, idaapi.cvar.inf.maxEA
        config.display_only_existing_strings = True
        config.only_7bit = True
        config.ignore_heads = False

        res = [idaapi.ASCSTR_TERMCHR, idaapi.ASCSTR_PASCAL, idaapi.ASCSTR_LEN2, idaapi.ASCSTR_UNICODE, idaapi.ASCSTR_LEN4, idaapi.ASCSTR_ULEN2, idaapi.ASCSTR_ULEN4]
        config.strtypes = reduce(lambda t, c: t | (2**c), res, 0)
        if not idaapi.set_strlist_options(config):
            raise internal.exceptions.DisassemblerError(u"{:s}.__on_openidb__({:#x}, {:b}) : Unable to set the default options for the string list.".format('.'.join((__name__, cls.__name__)), code, is_old_database))
        #assert idaapi.refresh_strlist(config.ea1, config.ea2), "{:#x}:{:#x}".format(config.ea1, config.ea2)

    # FIXME: I don't think that these callbacks are stackable
    idaapi.notify_when(idaapi.NW_OPENIDB, __on_openidb__)

    @classmethod
    def refresh(cls):
        '''Refresh the strings list.'''
        return idaapi.refresh_lists()
    @classmethod
    def size(cls):
        '''Return the number of elements in the strings list.'''
        return idaapi.get_strlist_qty()
    @classmethod
    @document.parameters(index='the index of the string item to return')
    def at(cls, index):
        '''Return the string at the specified `index`.'''
        si = idaapi.string_info_t()

        # FIXME: this isn't being used correctly
        res = idaapi.get_strlist_item(index, si)
        if not res:
            raise internal.exceptions.DisassemblerError(u"{:s}.at({:d}) : The call to `idaapi.get_strlist_item({:d})` returned {!r}.".format('.'.join((__name__, cls.__name__)), index, index, res))
        return si
    @classmethod
    @document.parameters(index='the index of the string to return')
    def get(cls, index):
        '''Return the address and the string at the specified `index`.'''
        si = cls.at(index)
        res = idaapi.get_ascii_contents(si.ea, si.length, si.type)
        return si.ea, internal.utils.string.of(res)
    @classmethod
    def iterate(cls):
        '''Iterate through all of the address and strings in the strings list.'''
        for index in six.moves.range(cls.size()):
            si = cls.at(index)
            res = idaapi.get_ascii_contents(si.ea, si.length, si.type)
            yield si.ea, internal.utils.string.of(res)
        return

@document.namespace
class segments(appwindow):
    """
    This namespace is for interacting with the Segments window.
    """
    __open__ = staticmethod(idaapi.open_segments_window)
    __open_defaults__ = (idaapi.BADADDR, )

@document.namespace
class notepad(appwindow):
    """
    This namespace is for interacting with the Notepad window.
    """
    __open__ = staticmethod(idaapi.open_notepad_window)
    __open_defaults__ = ()

@document.namespace
class timer(object):
    """
    This namespace is for registering a python callable to a timer in IDA.
    """
    clock = {}
    @classmethod
    @document.parameters(id='a unique id used to refer to the callable being registered in the timer', interval='what interval to execute the callable at', callable='a python callable to execute when the timer ticks')
    def register(cls, id, interval, callable):
        '''Register the specified `callable` with the requested `id` to be called at every `interval`.'''
        if id in cls.clock:
            idaapi.unregister_timer(cls.clock[id])

        # XXX: need to create a closure that can terminate when signalled
        cls.clock[id] = res = idaapi.register_timer(interval, callable)
        return res
    @classmethod
    @document.parameters(id='the unique id of the callable to unregister')
    def unregister(cls, id):
        '''Unregister the specified `id`.'''
        raise internal.exceptions.UnsupportedCapability(u"{:s}.unregister({!s}) : A lock or a signal is needed here in order to unregister this timer safely.".format('.'.join((__name__, cls.__name__)), id))
        idaapi.unregister_timer(cls.clock[id])
        del(cls.clock[id])
    @classmethod
    def reset(cls):
        '''Remove all the registered timers.'''
        for id, clk in six.iteritems(cls.clock):
            idaapi.unregister_timer(clk)
            del(cls.clock[id])
        return

### updating the state of the colored navigation band
@document.namespace
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
    @document.parameters(ea='the address to set the navigation bar pointer to')
    def set(cls, ea):
        '''Set the auto-analysis address on the navigation bar to `ea`.'''
        return cls.__set__(ea)

    @classmethod
    @document.parameters(ea='the address to set the auto-analysis address to on the navigation bar', type='if ``type`` is specified as an `idaapi.AU_*`, then use this as the navigation type')
    def auto(cls, ea, **type):
        """Set the auto-analysis address and type on the navigation bar to `ea`.

        If `type` is specified, then update using the specified auto-analysis type.
        """
        return cls.__auto__(ea, type.get('type', idaapi.AU_NONE))

    @classmethod
    @document.parameters(ea='the address to set the auto-analysis unknown address to on the navigation bar')
    def unknown(cls, ea): return cls.auto(ea, type=idaapi.AU_UNK)
    @classmethod
    @document.parameters(ea='the address to set the auto-analysis code address to on the navigation bar')
    def code(cls, ea): return cls.auto(ea, type=idaapi.AU_CODE)
    @classmethod
    @document.parameters(ea='the address to set the auto-analysis weak address to on the navigation bar')
    def weak(cls, ea): return cls.auto(ea, type=idaapi.AU_WEAK)
    @classmethod
    @document.parameters(ea='the address to set the auto-analysis procedure address to on the navigation bar')
    def procedure(cls, ea): return cls.auto(ea, type=idaapi.AU_PROC)
    @classmethod
    @document.parameters(ea='the address to set the auto-analysis tail address to on the navigation bar')
    def tail(cls, ea): return cls.auto(ea, type=idaapi.AU_TAIL)
    @classmethod
    @document.parameters(ea='the address to set the auto-analysis stackpointer address to on the navigation bar')
    def stackpointer(cls, ea): return cls.auto(ea, type=idaapi.AU_TRSP)
    @classmethod
    @document.parameters(ea='the address to set the auto-analysis analyze address to on the navigation bar')
    def analyze(cls, ea): return cls.auto(ea, type=idaapi.AU_USED)
    @classmethod
    @document.parameters(ea='the address to set the auto-analysis type address to on the navigation bar')
    def type(cls, ea): return cls.auto(ea, type=idaapi.AU_TYPE)
    @classmethod
    @document.parameters(ea='the address to set the auto-analysis signature address to on the navigation bar')
    def signature(cls, ea): return cls.auto(ea, type=idaapi.AU_LIBF)
    @classmethod
    @document.parameters(ea='the address to set the auto-analysis final address to on the navigation bar')
    def final(cls, ea): return cls.auto(ea, type=idaapi.AU_FINAL)

### interfacing with IDA's menu system
# FIXME: add some support for actually manipulating menus
@document.namespace
class menu(object):
    """
    This namespace is for registering items in IDA's menu system.
    """
    state = {}
    @classmethod
    @document.parameters(path='the menu path to add the item to', name='the name of the item to add', callable='the callable to execute when the item is clicked', hotkey='the key mapping to map the menu item to', args='any parameters to pass to the callable', flags='any extra flags to pass to `idaapi.add_menu_item`')
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
    @document.parameters(path='the menu path containing the item to remove', name='the name of the item to remove')
    def rm(cls, path, name):
        '''Remove the menu item at the specified `path` with the provided `name`.'''
        res = cls.state[path, name]
        idaapi.del_menu_item(res)
        del cls.state[path, name]
    @classmethod
    def reset(cls):
        '''Remove all currently registered menu items.'''
        for path, name in six.iterkeys(state):
            cls.rm(path, name)
        return

### Qt wrappers and namespaces
@document.namespace
class window(object):
    """
    This namespace is for selecting a specific or particular window.
    """
    @classmethod
    def viewer(cls):
        '''Return the current viewer.'''
        return idaapi.get_current_viewer()
    @classmethod
    def main(cls):
        '''Return the active main window.'''
        global application
        q = application()
        return q.activeWindow()

@document.namespace
class windows(object):
    """
    Interact with any or all of the top-level windows for the application.
    """
    def __new__(cls):
        '''Return all of the top-level windows.'''
        global application
        q = application()
        return q.topLevelWindows()

@document.namespace
class widget(object):
    """
    This namespace is for selecting a specific or particular widget.
    """
    @document.parameters(x='the X coordinate of the widget', y='the Y coordinate of the widget')
    def __new__(self, (x, y)):
        '''Return the widget at the specified `x` and `y` coordinate.'''
        res = (x, y)
        return cls.at(res)
    @classmethod
    @document.parameters(x='the X coordinate of the widget', y='the Y coordinate of the widget')
    def at(cls, (x, y)):
        '''Return the widget at the specified `x` and `y` coordinate.'''
        global application
        q = application()
        return q.widgetAt(x, y)
    @classmethod
    @document.parameters(twidget='the IDA plugin form to convert to a Qt widget')
    def form(cls, twidget):
        '''Return an IDA plugin form as a UI widget.'''
        raise internal.exceptions.MissingMethodError

@document.namespace
class clipboard(object):
    """
    This namespace is for interacting with the current clipboard state.
    """
    def __new__(cls):
        '''Return the current clipboard.'''
        global application
        clp = application()
        return clp.clipboard()

@document.namespace
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

@document.namespace
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

    hotkey = {}
    @document.aliases('keyboard.add')
    @classmethod
    @document.parameters(key='the key to map', callable='a python callable to execute when the specified key is pressed')
    def map(cls, key, callable):
        '''Map a specific `key` to a python `callable`.'''

        # check to see if the key is stored within our cache and remove it if so
        if key in cls.hotkey:
            idaapi.del_hotkey(cls.hotkey[key])

        # now we can add the hotkey and stash it in our cache
        # XXX: I'm not sure if the key needs to be utf8 encoded or not
        cls.hotkey[key] = res = idaapi.add_hotkey(key, callable)
        return res
    @document.aliases('keyboard.rm')
    @classmethod
    @document.parameters(key='the key mapping to unmap')
    def unmap(cls, key):
        '''Unmap the specified `key` from its callable.'''
        idaapi.del_hotkey(cls.hotkey[key])
        del(cls.hotkey[key])
    add, rm = internal.utils.alias(map, 'keyboard'), internal.utils.alias(unmap, 'keyboard')

    @classmethod
    def input(cls):
        '''Return the current keyboard input context.'''
        raise internal.exceptions.MissingMethodError

### PyQt5-specific functions and namespaces
## these can overwrite any of the classes defined above
try:
    import PyQt5.Qt
    from PyQt5.Qt import QObject

    @document.hidden
    def application():
        '''Return the current instance of the IDA Application.'''
        q = PyQt5.Qt.qApp
        return q.instance()

    @document.hidden
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

    @document.hidden
    class keyboard(keyboard):
        """
        This namespace is for interacting with the keyboard input.
        """
        @classmethod
        def input(cls):
            '''Return the current keyboard input context.'''
            raise internal.exceptions.MissingMethodError

    @document.classdef
    class UIProgress(object):
        """
        Helper class used to simplify the showing of a progress bar in IDA's UI.
        """
        timeout = 5.0

        @document.parameters(blocking='whether to render the progress bar synchronously or asynchronously')
        def __init__(self, blocking=True):
            self.object = res = PyQt5.Qt.QProgressDialog()
            res.setVisible(False)
            res.setWindowModality(blocking)
            res.setAutoClose(True)
            path = u"{:s}/{:s}".format(_database.config.path(), _database.config.filename())
            self.update(current=0, min=0, max=0, text=u'Processing...', tooltip=u'...', title=path)

        # properties
        canceled = property(fget=lambda s: s.object.wasCanceled(), fset=lambda s, v: s.object.canceled.connect(v))
        maximum = property(fget=lambda s: s.object.maximum())
        minimum = property(fget=lambda s: s.object.minimum())
        current = property(fget=lambda s: s.object.value())

        # methods
        @document.parameters(width="the percentage of IDA's dimensions to set the width to", height="the percentange of IDA's dimensions to set the height to")
        def open(self, width=0.8, height=0.1):
            '''Open a progress bar with the specified `width` and `height` relative to the dimensions of IDA's window.'''
            global window
            cls = self.__class__

            # XXX: spin for a second until main is defined because IDA seems to be racy with this api
            ts, main = time.time(), getattr(self, '__appwindow__', None)
            while time.time() - ts < self.timeout and main is None:
                main = window.main()

            if main is None:
                logging.warn(u"{:s}.open({!s}, {!s}) : Unable to find main application window. Falling back to default screen dimensions to calculate size.".format('.'.join((__name__, cls.__name__)), width, height))

            # figure out the dimensions of the window
            if main is None:
                # if there's no window, then assume some screen dimensions
                w, h = 1024, 768
            else:
                w, h = main.width(), main.height()

            # now we can calculate the dimensions of the progress bar
            logging.info(u"{:s}.open({!s}, {!s}) : Using dimensions ({:d}, {:d}) for progress bar.".format('.'.join((__name__, cls.__name__)), width, height, int(w*width), int(h*height)))
            self.object.setFixedWidth(w * width), self.object.setFixedHeight(h * height)

            # calculate the center
            if main is None:
                # no window, so use the center of the screen
                cx, cy = w * 0.5, h * 0.5
            else:
                center = main.geometry().center()
                cx, cy = center.x(), center.y()

            # ...and center it.
            x, y = cx - (w * width * 0.5), cy - (h * height * 1.0)
            logging.info(u"{:s}.open({!s}, {!s}) : Centering progress bar at ({:d}, {:d}).".format('.'.join((__name__, cls.__name__)), width, height, int(x), int(y)))
            self.object.move(x, y)

            # now everything should look good.
            self.object.show()

        def close(self):
            '''Close the current progress bar.'''
            self.object.close()

        @document.parameters(
            options="""
            The options to update the progress bar with. Some of these options are:

                - ``minimum`` - the minimum value on the progress bar
                - ``maximum`` - the maximum value on the progress bar
                - ``text`` - the current text to display
                - ``title`` - the title of the progress bar
                - ``tooltip`` - what to emit when the user hovers over the progress bar

            """
        )
        def update(self, **options):
            '''Update the current state of the progress bar.'''
            minimum, maximum = options.get('min', None), options.get('max', None)
            text, title, tooltip = (options.get(n, None) for n in ['text', 'title', 'tooltip'])

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

    @document.hidden
    class widget(widget):
        """
        This namespace is for selecting a specific or particular widget.
        """
        @classmethod
        @document.parameters(twidget='the IDA plugin form to convert to a Qt widget')
        def form(cls, twidget):
            '''Return an IDA plugin form as a UI widget.'''
            ns = idaapi.PluginForm
            return ns.FormToPyQtWidget(twidget)

except ImportError:
    logging.info(u"{:s}:Unable to locate `PyQt5.Qt` module.".format(__name__))

### PySide-specific functions and namespaces
try:
    import PySide
    import PySide.QtCore, PySide.QtGui

    @document.hidden
    def application():
        '''Return the current instance of the IDA Application.'''
        res = PySide.QtCore.QCoreApplication
        return res.instance()

    @document.hidden
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

    @document.hidden
    class keyboard(keyboard):
        """
        PySide keyboard interface.
        """
        @classmethod
        def input(cls):
            '''Return the current keyboard input context.'''
            return q.inputContext()

    @document.hidden
    class widget(widget):
        """
        This namespace is for selecting a specific or particular widget.
        """
        @classmethod
        @document.parameters(twidget='the IDA plugin form to convert to a Qt widget')
        def form(cls, twidget):
            '''Return an IDA plugin form as a UI widget.'''
            ns = idaapi.PluginForm
            return ns.FormToPySideWidget(twidget)

except ImportError:
    logging.info(u"{:s}:Unable to locate `PySide` module.".format(__name__))

### wrapper that uses a priorityhook around IDA's hooking capabilities.
@document.hidden
class hook(object):
    """
    This namespace exposes the ability to hook different parts of IDA.

    There are 3 different components in IDA that can be hooked. These
    are available as ``hook.idp``, ``hook.idb``, and ``hook.ui``.

    Please refer to the documentation for ``idaapi.IDP_Hooks``,
    ``idaapi.IDB_Hooks``, and ``idaapi.UI_Hooks`` for identifying what
    is available.
    """
    @classmethod
    def __start_ida__(cls):
        api = [
            ('idp', idaapi.IDP_Hooks),
            ('idb', idaapi.IDB_Hooks),
            ('ui', idaapi.UI_Hooks),
        ]
        priorityhook = internal.interface.priorityhook
        for attr, hookcls in api:
            if not hasattr(cls, attr):
                setattr(cls, attr, priorityhook(hookcls))
            continue
        return

    @classmethod
    def __stop_ida__(cls):
        for api in ['idp', 'idb', 'ui']:
            res = getattr(cls, api)

            # disable every single hook
            for name in res:
                res.disable(name)

            # unhook it completely, because IDA on linux seems to still dispatch to those hooks...even when the language extension is unloaded.
            res.remove()
        return

### for queueing the execution of a function asynchronously.
## (which is probably pretty unsafe in IDA, but let's hope).
@document.namespace
class queue(object):
    """
    This namespace exposes the ability to queue execution of python
    callables asynchronously so that they run at the same time as
    IDA and signal when they have completed and a result is available.

    XXX: This is probably pretty unsafe in IDA, but let's hope.
    """
    @classmethod
    def __start_ida__(cls):
        if hasattr(cls, 'execute') and not cls.execute.dead:
            logging.warn(u"{:s}.start() : Skipping re-instantiation of execution queue {!r}.".format('.'.join((__name__, cls.__name__)), cls.execute))
            return
        cls.execute = internal.utils.execution()
        return

    @classmethod
    def __stop_ida__(cls):
        if not hasattr(cls, 'execute'):
            logging.warn(u"{:s}.stop() : Refusing to release execution queue due to it not being initialized.".format('.'.join((__name__, cls.__name__))))
            return
        return cls.execute.release()

    @classmethod
    def __open_database__(cls, idp_modname):
        return cls.execute.start()

    @classmethod
    def __close_database__(cls):
        return cls.execute.stop()

    @classmethod
    @document.parameters(callable='the python callable to execute', args='any positional arguments to pass to the callable', kwds='any keyword arguments to pass to the callable')
    def add(cls, callable, *args, **kwds):
        '''Add the specified `callable` to the execution queue passing to it any extra arguments.'''
        if not cls.execute.running:
            logging.warn(u"{:s}.add(...) : Unable to execute {!r} due to queue not running.".format('.'.join((__name__, cls.__name__)), callable))
        return cls.execute.push(callable, *args, **kwds)

    @classmethod
    def pop(cls):
        '''Block until the next available result has been returned.'''
        return next(cls.execute)

### Helper classes to use or inherit from
# XXX: why was this base class implemented again??
@document.classdef
class InputBox(idaapi.PluginForm):
    """
    A class designed to be inherited from that can be used
    to interact with the user.
    """
    @document.parameters(form='an `idaapi.PluginForm` that is created')
    def OnCreate(self, form):
        '''A method to overload to be notified when the plugin form is created.'''
        self.parent = self.FormToPyQtWidget(form)

    @document.parameters(form='an `idaapi.PluginForm` that is created')
    def OnClose(self, form):
        '''A method to overload to be notified when the plugin form is destroyed.'''
        pass

    @document.parameters(caption='the title of the form to show', options='any flags to show the form with')
    def Show(self, caption, options=0):
        '''Show the form with the specified `caption` and `options`.'''
        res = internal.utils.string.to(caption)
        return super(InputBox, self).Show(res, options)

### Console-only progress bar
@document.classdef
class ConsoleProgress(object):
    """
    Helper class used to simplify the showing of a progress bar in IDA's console.
    """
    def __init__(self, blocking=True):
        self.__path__ = u"{:s}/{:s}".format(_database.config.path(), _database.config.filename())
        self.__value__ = 0
        self.__min__, self.__max__ = 0, 0
        return

    canceled = property(fget=lambda s: False, fset=lambda s, v: None)
    maximum = property(fget=lambda s: self.__max__)
    minimum = property(fget=lambda s: self.__min__)
    current = property(fget=lambda s: self.__value__)

    @document.parameters(width="the percentage of IDA's dimensions to set the width to", height="the percentange of IDA's dimensions to set the height to")
    def open(self, width=0.8, height=0.1):
        '''Open a progress bar with the specified `width` and `height` relative to the dimensions of IDA's window.'''
        return

    def close(self):
        '''Close the current progress bar.'''
        return

    @document.parameters(
        options="""
        The options to update the progress bar with. Some of these options are:

            - ``minimum`` - the minimum value on the progress bar
            - ``maximum`` - the maximum value on the progress bar
            - ``text`` - the current text to display
            - ``title`` - the title of the progress bar
            - ``tooltip`` - what to emit when the user hovers over the progress bar

        """
    )
    def update(self, **options):
        '''Update the current state of the progress bar.'''
        minimum, maximum = options.get('min', None), options.get('max', None)
        text, title, tooltip = (options.get(n, None) for n in ['text', 'title', 'tooltip'])

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
@document.classdef
class Progress(object):
    """
    The default progress bar in with which to show progress. This class will
    automatically determine which progress bar (Console or UI) to instantiate
    based on what is presently available.
    """

    timeout = 5.0

    @document.parameters(args='any variable arguments to pass to the determined progress bar', kwargs='any keyword arguments to pass to the determined progress bar')
    def __new__(cls, *args, **kwargs):
        '''Figure out which progress bar to use and instantiate it with the provided parameters `args` and `kwargs`.'''
        if 'UIProgress' not in globals():
            logging.warn(u"{:s}(...) : Using console-only implementation of the `ui.Progress` class.".format('.'.join((__name__, cls.__name__))))
            return ConsoleProgress(*args, **kwargs)

        # XXX: spin for a bit looking for the application window as IDA seems to be racy with this for some reason
        ts, main = time.time(), getattr(cls, '__appwindow__', None)
        while time.time() - ts < cls.timeout and main is None:
            main = window.main()

        # If no main window was found, then fall back to the console-only progress bar
        if main is None:
            logging.warn(u"{:s}(...) : Unable to find main application window. Falling back to console-only implementation of the `ui.Progress` class.".format('.'.join((__name__, cls.__name__))))
            return ConsoleProgress(*args, **kwargs)

        cls.__appwindow__ = main
        return UIProgress(*args, **kwargs)
