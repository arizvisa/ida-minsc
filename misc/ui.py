import six
import sys,os
import logging

import idaapi
import internal,database,segment,function,instruction as ins,structure

## TODO:
# locate window under current cursor position
# pop-up a menu item
# pop-up a form/messagebox
# another item menu to toolbar
# find the QAction associated with a command (or keypress)

class current(object):
    """
    Fetching things from current visual state.

    Pretty much used for doing friendly user-interface type stuff.
    """
    @classmethod
    def address(cls):
        """Current address"""
        return idaapi.get_screen_ea()
    @classmethod
    def widget(cls):
        """Current widget"""
        x,y = Input.mouse.position()
        return Input.at((x,y))
    @classmethod
    def color(cls):
        """Current color"""
        ea = cls.address()
        return idaapi.get_item_color(ea)
    @classmethod
    def function(cls):
        """Current function"""
        ea = cls.address()
        res = idaapi.get_func(ea)
        if res is None:
            raise StandardError("{:s}.function : Not currently inside a function.".format('.'.join((__name__, cls.__name__))))
        return res
    @classmethod
    def segment(cls):
        """Current segment"""
        ea = cls.address()
        return idaapi.getseg(ea)
    @classmethod
    def status(cls):
        """IDA Status"""
        raise NotImplementedError
    @classmethod
    def symbol(cls):
        """Return the symbol name directly under the cursor"""
        return idaapi.get_highlighted_identifier()
    @classmethod
    def selection(cls):
        view = idaapi.get_current_viewer()
        left, right = idaapi.twinpos_t(), idaapi.twinpos_t()
        ok = idaapi.read_selection(view, left, right)
        if not ok:
            raise StandardError("{:s}.selection : Unable to read selection.".format('.'.join((__name__, cls.__name__))))
        pl_l, pl_r = left.place(view), right.place(view)
        return database.address.head(pl_l.ea), database.address.tail(pl_r.ea)

try:
    import PyQt5.Qt
    from PyQt5.Qt import QObject

    class root(object):
        """
        Get information about the root Qt objects in IDA.
        """
        @classmethod
        def application(cls):
            return PyQt5.Qt.qApp
        @classmethod
        def window(cls):
            return max(cls.windows(), key=lambda w: w.width() * w.height())
        @classmethod
        def windows(cls):
            q = cls.application()
            return q.topLevelWindows()
        @classmethod
        def refresh(cls):
            idaapi.refresh_lists()
            return idaapi.refresh_idaview_anyway()

    class progress(object):
        """
        Helper class for showing a progress-bar.
        """
        def __init__(self, blocking=True):
            self.object = res = PyQt5.Qt.QProgressDialog()
            res.setVisible(False)
            res.setWindowModality(blocking)
            res.setAutoClose(True)
            path = "{:s}/{:s}".format(database.path(), database.filename())
            self.update(current=0, min=0, max=0, text='Processing...', tooltip='...', title=path)

        # properties
        canceled = property(fget=lambda s: s.object.wasCanceled(), fset=lambda s,v: s.object.canceled.connect(v))
        maximum = property(fget=lambda s: s.object.maximum())
        minimum = property(fget=lambda s: s.object.minimum())
        current = property(fget=lambda s: s.object.value())

        # methods
        def open(self, width=0.8, height=0.1):
            global root
            window = root.window()
            w, h = window.width() * width, window.height() * height
            self.object.setFixedWidth(w), self.object.setFixedHeight(h)

            center = window.geometry().center()
            x, y = center.x() - (w * 0.5), center.y() - (h * 1.0)
            self.object.move(x, y)

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

except ImportError:
    logging.warn("{:s}:Unable to import PyQt5.Qt. Using console-only variation of ui module.".format(__name__))

    class root(object):
        @classmethod
        def application(cls):
            return PyQt5.Qt.qApp
        @classmethod
        def window(cls):
            return max(cls.windows(), key=lambda w: w.width() * w.height())
        @classmethod
        def windows(cls):
            q = cls.application()
            return q.topLevelWindows()
        @classmethod
        def refresh(cls):
            idaapi.refresh_lists()
            return idaapi.refresh_idaview_anyway()

    class progress(object):
        def __init__(self, blocking=True):
            self.__path__ = "{:s}/{:s}".format(database.path(), database.filename())
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

class InputBox(idaapi.PluginForm):
    """Creating an InputBox to interact with the user"""
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)

    def OnClose(self, form):
        pass

    def Show(self, caption, options=0):
        return super(InputBox,self).Show(caption, options)

class Names(object):
    """
    Getting information about the Names window.
    """
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

class Strings(object):
    """
    Grabbing contents from the Strings window
    """

    @classmethod
    def on_openidb(cls, code, is_old_database):
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
        #assert idaapi.refresh_strlist(config.ea1, config.ea2), "{:x}:{:x}".format(config.ea1, config.ea2)

    # FIXME: I don't think that these callbacks are stackable
    idaapi.notify_when(idaapi.NW_OPENIDB, on_openidb)

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

try:
    # FIXME: switch over to PyQt5
    import PyQt5.Qt

    class UI(object):
        '''static class for interacting with IDA's Qt user-interface'''
        @classmethod
        def application(cls):
            return PyQt5.Qt.qApp
            #return PyQt5.Qt.QApplication.instance()

        @classmethod
        def clipboard(cls):
            clp = cls.application().clipboard()
            clp = utils.multicase()

        @classmethod
        def main(cls):
            """Return the current active window"""
            return cls.application().activeWindow()

        @classmethod
        def at(cls, (x,y)):
            """Return the QWidget under the specific coordinate"""
            return cls.application().widgetAt(x,y)

        class mouse(object):
            """mouse interface"""
            @classmethod
            def position(cls):
                res = PySide.QtGui.QCursor.pos()
                return res.x(),res.y()
            @classmethod
            def buttons(cls):
                return Input.application().mouseButtons()

        class keyboard(object):
            """keyboard interface"""
            @classmethod
            def modifiers(cls):
                return Input.application().keyboardModifiers()
            @classmethod
            def input(cls):
                return Input.application().inputContext()

            hotkey = {}
            @classmethod
            def add(cls, key, fn):
                """map a key to a python function"""
                if key in cls.hotkey:
                    idaapi.del_hotkey(cls.hotkey[key])
                cls.hotkey[key] = res = idaapi.add_hotkey(key, fn)
                return res
            @classmethod
            def rm(cls, key):
                """unmap a key"""
                idaapi.del_hotkey(cls.hotkey[key])
                del(cls.hotkey[key])

        # FIXME: idaapi timer's are racy and can crash ida
        class timer(object):
            clock = {}
            @classmethod
            def register(cls, id, interval, fn):
                """register a python function as a timer"""
                if id in cls.clock:
                    idaapi.unregister_timer(cls.clock[id])

                # XXX: need to create a closure that can terminate when signalled
                cls.clock[id] = res = idaapi.register_timer(interval, fn)
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

        # FIXME: add some support for actually manipulating menus
        class menu(object):
            state = {}
            @classmethod
            def add(cls, path, name, fn, hotkey='', flags=0, args=()):
                if (path,name) in cls.state:
                    cls.rm(path, name)
                ctx = idaapi.add_menu_item(path, name, hotkey, flags, fn, args)
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

except ImportError:
    logging.warn("__module__ : {:s} : Unable to load PyQt5.Qt module. Certain UI.* methods might not work.".format(__name__))

# for exposing the ability queueing functions asynchronously..
# which is probably pretty unsafe in IDA, but let's hope.
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
    def add(cls, func, *args, **kwds):
        if not cls.execute.running:
            logging.warn("{:s}.add : Unable to execute {!r} due to queue not running.".format('.'.join((__name__, cls.__name__)), func))
        return cls.execute.push(func, *args, **kwds)

    @classmethod
    def pop(cls):
        return next(cls.execute)

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
