import six
import sys,os
import logging

import idaapi, internal
import database as _database

## TODO:
# locate window under current cursor position
# pop-up a menu item
# pop-up a form/messagebox
# another item menu to toolbar
# find the QAction associated with a command (or keypress)

class current(object):
    """
    Fetching things from current visual state.

    Used to fetch information about what the user has currently selected.
    """
    @classmethod
    def address(cls):
        '''Current address'''
        return idaapi.get_screen_ea()
    @classmethod
    def color(cls):
        '''Current color'''
        ea = cls.address()
        return idaapi.get_item_color(ea)
    @classmethod
    def function(cls):
        '''Current function'''
        ea = cls.address()
        res = idaapi.get_func(ea)
        if res is None:
            raise StandardError("{:s}.function : Not currently inside a function.".format('.'.join((__name__, cls.__name__))))
        return res
    @classmethod
    def segment(cls):
        '''Current segment'''
        ea = cls.address()
        return idaapi.getseg(ea)
    @classmethod
    def status(cls):
        '''IDA Status'''
        raise NotImplementedError
    @classmethod
    def symbol(cls):
        '''Return the symbol name directly under the cursor'''
        return idaapi.get_highlighted_identifier()
    @classmethod
    def selection(cls):
        '''Return the current address range of whatever is selected'''
        view = idaapi.get_current_viewer()
        left, right = idaapi.twinpos_t(), idaapi.twinpos_t()
        ok = idaapi.read_selection(view, left, right)
        if not ok:
            raise StandardError("{:s}.selection : Unable to read selection.".format('.'.join((__name__, cls.__name__))))
        pl_l, pl_r = left.place(view), right.place(view)
        return _database.address.head(pl_l.ea), _database.address.tail(pl_r.ea)
    @classmethod
    def opnum(cls):
        return idaapi.get_opnum()
    @classmethod
    def widget(cls):
        '''Current widget'''
        # XXX: there's probably a better way to do this rather than looking
        #      at the mouse cursor position
        x, y = mouse.position()
        return widget.at((x,y))
    @classmethod
    def window(cls):
        '''Return the current window that is being used.'''
        global window
        # FIXME: cast this to a QWindow somehow?
        return window.main()

class state(object):
    """
    Class for interacting with the state of IDA's interface.
    """
    @classmethod
    def graphview(cls):
        """Returns `True` if the current function is being viewed in graph view mode."""
        res = idaapi.get_inf_structure()
        if idaapi.__version__ < 7.0:
            return res.graph_view != 0
        return res.is_graph_view()

    @classmethod
    def wait(cls):
        '''Wait until IDA's autoanalysis queues are empty.'''
        return idaapi.autoWait() if idaapi.__version__ < 7.0 else idaapi.auto_wait()

def beep():
    return idaapi.beep()

def refresh():
    '''Refresh all of IDA's windows.'''
    global disassembly
    idaapi.refresh_lists()
    disassembly.refresh()

class appwindow(object):
    @classmethod
    def open(cls, *args):
        global widget
        res = cls.__open__(*args) if args else cls.__open__(*getattr(cls, '__open_defaults__', ()))
        return widget.form(res)

    @classmethod
    def close(cls):
        res = cls.open()
        return res.deleteLater()

class disassembly(appwindow):
    """
    Interacting with the Disassembly window.
    """
    __open__ = staticmethod(idaapi.open_disasm_window)
    __open_defaults__ = ('Disassembly', )

    @classmethod
    def refresh(cls):
        '''Refresh the main IDA disassembly view.'''
        return idaapi.refresh_idaview_anyway()

class exports(appwindow):
    """
    Interacting with the Exports window.
    """
    __open__ = staticmethod(idaapi.open_exports_window)
    __open_defaults__ = (idaapi.BADADDR, )

class imports(appwindow):
    """
    Interacting with the Imports window.
    """
    __open__ = staticmethod(idaapi.open_imports_window)
    __open_defaults__ = (idaapi.BADADDR, )

class names(appwindow):
    """
    Interacting with the Names window.
    """
    __open__ = staticmethod(idaapi.open_names_window)
    __open_defaults__ = (idaapi.BADADDR, )

    @classmethod
    def refresh(cls):
        return idaapi.refresh_lists()
    @classmethod
    def size(cls):
        return idaapi.get_nlist_size()
    @classmethod
    def contains(cls, ea):
        return idaapi.is_in_nlist(ea)
    @classmethod
    def search(cls, ea):
        return idaapi.get_nlist_idx(ea)

    @classmethod
    def at(cls, index):
        return idaapi.get_nlist_ea(index),idaapi.get_nlist_name(index)
    @classmethod
    def name(cls, index):
        return idaapi.get_nlist_name(index)
    @classmethod
    def ea(cls, index):
        return idaapi.get_nlist_ea(index)

    @classmethod
    def iterate(cls):
        for idx in six.moves.range(cls.size()):
            yield cls.at(idx)
        return

class functions(appwindow):
    """
    Interacting with the Functions window.
    """
    __open__ = staticmethod(idaapi.open_funcs_window)
    __open_defaults__ = (idaapi.BADADDR, )

class structures(appwindow):
    """
    Interacting with the Structures window.
    """
    __open__ = staticmethod(idaapi.open_structs_window)
    __open_defaults__ = (idaapi.BADADDR, 0)

class strings(appwindow):
    """
    Interacting with the Strings window.
    """
    __open__ = staticmethod(idaapi.open_strings_window)
    __open_defaults__ = (idaapi.BADADDR, idaapi.BADADDR, idaapi.BADADDR)

    @classmethod
    def __on_openidb__(cls, code, is_old_database):
        if code != idaapi.NW_OPENIDB or is_old_database:
            raise RuntimeError
        config = idaapi.strwinsetup_t()
        config.minlen = 3
        config.ea1,config.ea2 = idaapi.cvar.inf.minEA,idaapi.cvar.inf.maxEA
        config.display_only_existing_strings = True
        config.only_7bit = True
        config.ignore_heads = False

        res = [idaapi.ASCSTR_TERMCHR,idaapi.ASCSTR_PASCAL,idaapi.ASCSTR_LEN2,idaapi.ASCSTR_UNICODE,idaapi.ASCSTR_LEN4,idaapi.ASCSTR_ULEN2,idaapi.ASCSTR_ULEN4]
        config.strtypes = reduce(lambda t,c: t | (2**c), res, 0)
        assert idaapi.set_strlist_options(config)
        #assert idaapi.refresh_strlist(config.ea1, config.ea2), "{:#x}:{:#x}".format(config.ea1, config.ea2)

    # FIXME: I don't think that these callbacks are stackable
    idaapi.notify_when(idaapi.NW_OPENIDB, __on_openidb__)

    @classmethod
    def refresh(cls):
        return idaapi.refresh_lists()
    @classmethod
    def size(cls):
        return idaapi.get_strlist_qty()
    @classmethod
    def at(cls, index):
        string = idaapi.string_info_t()
        res = idaapi.get_strlist_item(index, string)
        if not res:
            raise RuntimeError, "idaapi.get_strlist_item({:d}) -> {!r}".format(index, res)
        return string
    @classmethod
    def get(cls, index):
        si = cls.at(index)
        return si.ea, idaapi.get_ascii_contents(si.ea, si.length, si.type)
    @classmethod
    def iterate(cls):
        for index in six.moves.range(cls.size()):
            si = cls.at(index)
            yield si.ea, idaapi.get_ascii_contents(si.ea, si.length, si.type)
        return

class segments(appwindow):
    """
    Interacting with the Segments window.
    """
    __open__ = staticmethod(idaapi.open_segments_window)
    __open_defaults__ = (idaapi.BADADDR, )

class notepad(appwindow):
    """
    Interacting with the Notepad window.
    """
    __open__ = staticmethod(idaapi.open_notepad_window)
    __open_defaults__ = ()

class timer(object):
    clock = {}
    @classmethod
    def register(cls, id, interval, callable):
        """register a python function as a timer"""
        if id in cls.clock:
            idaapi.unregister_timer(cls.clock[id])

        # XXX: need to create a closure that can terminate when signalled
        cls.clock[id] = res = idaapi.register_timer(interval, callable)
        return res
    @classmethod
    def unregister(cls, id):
        raise NotImplementedError('need a lock or signal here')
        idaapi.unregister_timer(cls.clock[id])
        del(cls.clock[id])
    @classmethod
    def reset(cls):
        """remove all timers"""
        for id, clk in six.iteritems(cls.clock):
            idaapi.unregister_timer(clk)
            del(cls.clock[id])
        return

### updating the state of the colored navigation band
class navigation(object):
    """
    Exposes the ability to update the state of the colored navigation band.
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
        '''Set the auto-analysis address on the navigation bar to ``ea``.'''
        return cls.__set__(ea)

    @classmethod
    def auto(cls, ea, **type):
        """Set the auto-analysis address and type on the navigation bar to ``ea``.
        If ``type`` is specified, then update using the specified auto-analysis type.
        """
        return cls.__auto__(ea, type.get('type', idaapi.AU_NONE))

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
    state = {}
    @classmethod
    def add(cls, path, name, callable, hotkey='', flags=0, args=()):
        if (path,name) in cls.state:
            cls.rm(path, name)
        ctx = idaapi.add_menu_item(path, name, hotkey, flags, callable, args)
        cls.state[path,name] = ctx
    @classmethod
    def rm(cls, path, name):
        idaapi.del_menu_item( cls.state[path,name] )
        del cls.state[path,name]
    @classmethod
    def reset(cls):
        for path, name in six.iterkeys(state):
            cls.rm(path,name)
        return

### Qt wrappers and namespaces
def application():
    raise NotImplementedError

class window(object):
    """
    selecting a specific or particular window.
    """
    @classmethod
    def viewer(cls):
        return idaapi.get_current_viewer()
    @classmethod
    def main(cls):
        """Return the active main window"""
        global application
        q = application()
        return q.activeWindow()

class windows(object):
    """
    enumerating and filtering all the window types that are available.
    """
    def __new__(cls):
        global application
        q = application()
        return q.topLevelWindows()

class widget(object):
    """
    selecting a specific or particular widget.
    """
    def __new__(self, (x, y)):
        res = (x, y)
        return cls.at(res)
    @classmethod
    def at(cls, (x, y)):
        global application
        q = application()
        return q.widgetAt(x, y)
    @classmethod
    def form(cls, twidget):
        raise NotImplementedError

class clipboard(object):
    """
    interacting with the clipboard state.
    """
    def __new__(cls):
        global application
        clp = application()
        return clp.clipboard()

class mouse(object):
    '''mouse interface'''
    @classmethod
    def buttons(cls):
        global application
        q = application()
        return q.mouseButtons()

class keyboard(object):
    '''keyboard interface'''
    @classmethod
    def modifiers(cls):
        global application
        q = application()
        return q.keyboardModifiers()

    hotkey = {}
    @classmethod
    def map(cls, key, callable):
        '''map a key to a python function'''
        if key in cls.hotkey:
            idaapi.del_hotkey(cls.hotkey[key])
        cls.hotkey[key] = res = idaapi.add_hotkey(key, callable)
        return res
    @classmethod
    def unmap(cls, key):
        '''unmap a key'''
        idaapi.del_hotkey(cls.hotkey[key])
        del(cls.hotkey[key])
    add, rm = internal.utils.alias(map, 'keyboard'), internal.utils.alias(unmap, 'keyboard')

### PyQt5-specific functions and namespaces
## these can overwrite any of the classes defined above
try:
    import PyQt5.Qt
    from PyQt5.Qt import QObject

    def application():
        q = PyQt5.Qt.qApp
        return q.instance()

    class mouse(mouse):
        '''mouse interface'''
        @classmethod
        def position(cls):
            qt = PyQt5.QtGui.QCursor
            res = qt.pos()
            return res.x(), res.y()

    class keyboard(keyboard):
        '''PyQt5 keyboard interface'''
        @classmethod
        def input(cls):
            raise NotImplementedError

    class UIProgress(object):
        """
        Helper class used to construct and show a progress-bar in PyQt5.
        """
        def __init__(self, blocking=True):
            self.object = res = PyQt5.Qt.QProgressDialog()
            res.setVisible(False)
            res.setWindowModality(blocking)
            res.setAutoClose(True)
            path = "{:s}/{:s}".format(_database.path(), _database.filename())
            self.update(current=0, min=0, max=0, text='Processing...', tooltip='...', title=path)

        # properties
        canceled = property(fget=lambda s: s.object.wasCanceled(), fset=lambda s,v: s.object.canceled.connect(v))
        maximum = property(fget=lambda s: s.object.maximum())
        minimum = property(fget=lambda s: s.object.minimum())
        current = property(fget=lambda s: s.object.value())

        # methods
        def open(self, width=0.8, height=0.1):
            global window

            # XXX: spin until main is defined because IDA seems to be racy..
            main = None
            while main is None:
                main = window.main()

            # now we can calculate the dimensions of the progress bar
            w, h = main.width() * width, main.height() * height
            self.object.setFixedWidth(w), self.object.setFixedHeight(h)

            # ...and center it.
            center = main.geometry().center()
            x, y = center.x() - (w * 0.5), center.y() - (h * 1.0)
            self.object.move(x, y)

            # now everything should look good.
            self.object.show()

        def close(self):
            self.object.close()

        def update(self, **options):
            minimum, maximum = options.get('min', None), options.get('max', None)
            text, title, tooltip = (options.get(n, None) for n in ['text', 'title', 'tooltip'])

            if minimum is not None:
                self.object.setMinimum(minimum)
            if maximum is not None:
                self.object.setMaximum(maximum)
            if title is not None:
                self.object.setWindowTitle(title)
            if tooltip is not None:
                self.object.setToolTip(tooltip)
            if text is not None:
                self.object.setLabelText(text)

            res = self.object.value()
            if 'current' in options:
                self.object.setValue(options['current'])
            elif 'value' in options:
                self.object.setValue(options['value'])
            return res

    class widget(widget):
        @classmethod
        def form(cls, twidget):
            ns = idaapi.PluginForm
            return ns.FormToPyQtWidget(twidget)

except ImportError:
    logging.warn("{:s}:Unable to locate PyQt5.Qt module.".format(__name__))

### PySide-specific functions and namespaces
try:
    import PySide
    import PySide.QtCore, PySide.QtGui

    def application():
        res = PySide.QtCore.QCoreApplication
        return res.instance()

    class mouse(mouse):
        """mouse interface"""
        @classmethod
        def position(cls):
            qt = PySide.QtGui.QCursor
            res = qt.pos()
            return res.x(), res.y()

    class keyboard(keyboard):
        """PySide keyboard interface"""
        @classmethod
        def input(cls):
            return q.inputContext()

    class widget(widget):
        @classmethod
        def form(cls, twidget):
            ns = idaapi.PluginForm
            return ns.FormToPySideWidget(twidget)

except ImportError:
    logging.warn("{:s}:Unable to locate PySide module.".format(__name__))

### wrapper that uses a priorityhook around IDA's hooking capabilities.
class hook(object):
    """
    Exposes the ability of hooking different parts of IDA.
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
class queue(object):
    """
    Exposes the ability to queue the execution of functions so they
    run asynchronously.

    This is probably pretty unsafe in IDA, but let's hope.
    """
    @classmethod
    def __start_ida__(cls):
        if hasattr(cls, 'execute') and not cls.execute.dead:
            logging.warn("{:s}.start : Skipping re-instantiation of execution queue. : {!r}".format('.'.join((__name__, cls.__name__)), cls.execute))
            return
        cls.execute = internal.utils.execution()
        return

    @classmethod
    def __stop_ida__(cls):
        if not hasattr(cls, 'execute'):
            logging.warn("{:s}.stop : Refusing to release execution queue due to it not being initialized.".format('.'.join((__name__, cls.__name__))))
            return
        return cls.execute.release()

    @classmethod
    def __open_database__(cls, idp_modname):
        return cls.execute.start()

    @classmethod
    def __close_database__(cls):
        return cls.execute.stop()

    @classmethod
    def add(cls, callable, *args, **kwds):
        if not cls.execute.running:
            logging.warn("{:s}.add : Unable to execute {!r} due to queue not running.".format('.'.join((__name__, cls.__name__)), callable))
        return cls.execute.push(callable, *args, **kwds)

    @classmethod
    def pop(cls):
        return next(cls.execute)

### Helper classes to use or inherit from
# XXX: why was this base class implemented again??
class InputBox(idaapi.PluginForm):
    """Creating an InputBox to interact with the user"""
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)

    def OnClose(self, form):
        pass

    def Show(self, caption, options=0):
        return super(InputBox,self).Show(caption, options)

### figure out which progress-bar to define as `Progress`.
# if a UIProgress one was successfully defined, then use that one.
if 'UIProgress' in locals():
    class Progress(UIProgress): pass

# otherwise we just fall-back to the console-only one.
else:
    logging.warn("{:s}:Using console-only implementation of the ui.progress class.".format(__name__))
    class ConsoleProgress(object):
        """
        Helper class used to construct and show a progress-bar using the console.
        """
        def __init__(self, blocking=True):
            self.__path__ = "{:s}/{:s}".format(_database.path(), _database.filename())
            self.__value__ = 0
            self.__min__, self.__max__ = 0, 0
            return

        canceled = property(fget=lambda s: False, fset=lambda s,v: None)
        maximum = property(fget=lambda s: self.__max__)
        minimum = property(fget=lambda s: self.__min__)
        current = property(fget=lambda s: self.__value__)

        def open(self, width=0.8, height=0.1):
            return

        def close(self):
            return

        def update(self, **options):
            minimum, maximum = options.get('min', None), options.get('max', None)
            text,title,tooltip = (options.get(n, None) for n in ['text', 'title', 'tooltip'])

            if minimum is not None:
                self.__min__ = minimum
            if maximum is not None:
                self.__max__ = maximum

            if 'current' in options:
                self.__value__ = options['current']
            if 'value' in options:
                self.__value__ = options['value']

            logging.info(text)
            return self.__value__
    class Progress(ConsoleProgress): pass

def ask(string, **default):
    state = {'no': 0, 'yes': 1, 'cancel': -1}
    results = {0: False, 1: True}
    if default:
        keys = {n for n in default.viewkeys()}
        keys = {n.lower() for n in keys if default.get(n, False)}
        dflt = next((k for k in keys), 'cancel')
    else:
        dflt = 'cancel'
    res = idaapi.ask_yn(state[dflt], string)
    return results.get(res, None)
