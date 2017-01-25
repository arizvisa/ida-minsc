import logging
import internal,database,segment,function,instruction as ins,structure
import os

import PyQt5.Qt
from PyQt5.Qt import QObject
import idaapi

## TODO:
# locate window under current cursor position
# pop-up a menu item
# pop-up a form/messagebox
# another item menu to toolbar
# find the QAction associated with a command (or keypress)

class current(object):
    """Fetching things from current visual state.

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
            raise StandardError("{:s}.{:s}.function : Not currently inside a function.".format(__name__, cls.__name__))
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
        self.object = res = PyQt5.Qt.QProgressDialog()
        res.setVisible(False)
        res.setWindowModality(blocking)
        res.setAutoClose(True)
        path = '{:s}/{:s}'.format(database.path(), database.filename())
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
        text,title,tooltip = (options.get(n, None) for n in ('text','title','tooltip'))

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

class ProgressBar(object):
    """
    int progressDialog()
    {
     QProgressDialog dialog("Bytes received", "Stop reading", 0, 100); // expect 100 bytes
     PipeReader reader(fileno(stdin));
     QObject::connect(&reader, &PipeReader::channelClosed,
     &dialog, &QProgressDialog::accept);
     QObject::connect(&reader, &PipeReader::dataReceived, [&](const QByteArray &data) {
         qDebug() << "Received" << data.length() << "bytes";
         dialog.setValue(qMin(dialog.maximum(), dialog.value() + data.length()));
     });
     dialog.exec();
     return dialog.result() == QDialog::Accepted ? 0 : 1;
    }
    """

#.setModal
#.setRange
#.setLabelText
#.setMaximum
#.setMinimum
#.setValue
#.setWindowTitle
#.setStatusTip
#.setToolTip
#.setSizeHint
#.setWindowRole
#?.setWindowState

class ProgressBar(object):
    def __init__(self, title):
        pass
    def show(self, state):
        pass
    def start(self):
        pass
    def stop(self):
        pass
    def update(self, minimum, maximum, current):
        pass

class InputBox(idaapi.PluginForm):
    """Creating an InputBox to interact with the user"""
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)

    def OnClose(self, form):
        pass

    def Show(self, caption, options=0):
        return super(InputBox,self).Show(caption, options)

#import symath
#from symath.directed import DirectedGraph

#class navigation(object):
#    pass

class Names(object):
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
        for idx in xrange(cls.size()):
            yield cls.at(idx)
        return

class Strings(object):
    """Grabbing contents from the Strings window"""

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
        #assert idaapi.refresh_strlist(config.ea1, config.ea2), '{:x}:{:x}'.format(config.ea1, config.ea2)

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
            raise RuntimeError, 'idaapi.get_strlist_item({:d}) -> {!r}'.format(index, res)
        return string
    @classmethod
    def get(cls, index):
        si = cls.at(index)
        return si.ea, idaapi.get_ascii_contents(si.ea, si.length, si.type)
    @classmethod
    def iterate(cls):
        for index in xrange(cls.size()):
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
                for i,x in cls.clock.iteritems():
                    idaapi.unregister_timer(x)
                    del( cls.clock[i] )
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
                for path,name in state.keys():
                    cls.rm(path,name)
                return

    #class MenuItem(QtGui.

except ImportError:
    logging.warn("__module__ : {:s} : Unable to load PySide.QtGui module. Certain UI.* methods might not work.".format(__name__))

def above(ea, includeSegment=False):
    '''Display all the callers of the function at /ea/'''
    tryhard = lambda ea: '{:s}+{:x}'.format(database.name(function.top(ea)),ea-function.top(ea)) if function.within(ea) else '+{:x}'.format(ea) if database.name(ea) is None else database.name(ea)
    return '\n'.join(':'.join((segment.name(ea),tryhard(ea)) if includeSegment else (tryhard(ea),)) for ea in function.up(ea))

def below(ea, includeSegment=False):
    '''Display all the functions that the function at /ea/ can call'''
    tryhard = lambda ea: '{:s}+{:x}'.format(database.name(function.top(ea)),ea-function.top(ea)) if function.within(ea) else '+{:x}'.format(ea) if database.name(ea) is None else database.name(ea)
    return '\n'.join(':'.join((segment.name(ea),tryhard(ea)) if includeSegment else (tryhard(ea),)) for ea in function.down(ea))

# FIXME: this only works on x86 where args are pushed via stack
def makecall(ea=None, target=None):
    ea = current.address() if ea is None else ea
    if not function.contains(ea, ea):
        return None

    if database.config.bits() != 32:
        raise RuntimeError("{:s}.makecall({!r},{!r}) : Unable to determine arguments for {:s} due to {:d}-bit calling convention.".format(__name__, ea, target, database.disasm(ea), database.config.bits()))

    if target is None:
        # scan down until we find a call that references something
        chunk, = ((l,r) for l,r in function.chunks(ea) if l <= ea <= r)
        result = []
        while (len(result) < 1) and ea < chunk[1]:
            # FIXME: it's probably not good to just scan for a call
            if not database.instruction(ea).startswith('call '):
                ea = database.next(ea)
                continue
            result = database.cxdown(ea)
            if len(result) == 0: raise TypeError('{:s}.makecall({!r},{!r}) : Unable to determine number of arguments'.format(__name__, ea, target))

        if len(result) != 1:
            raise ValueError('{:s}.makecall({!r},{!r}) : Too many targets for call at {:x} : {!r}'.format(__name__, ea, result))
        fn, = result
    else:
        fn = target

    try:
        result = []
        for offset,name,size in function.arguments(fn):
            left,_ = function.stack_window(ea, offset+database.config.bits()/8)
            # FIXME: if left is not an assignment or a push, find last assignment
            result.append((name,left))
    except LookupError:
        raise LookupError("{:s}.makecall({!r},{!r}) : Unable to get arguments for target function".format(__name__, ea, target))

    # FIXME: replace these crazy list comprehensions with something more comprehensible.
#    result = ['{:s}={:s}'.format(name,ins.op_repr(ea, 0)) for name,ea in result]
    result = ['({:x}){:s}={:s}'.format(ea, name, ':'.join(ins.op_repr(database.address.prevreg(ea, ins.op_value(ea,0), write=1), n) for n in ins.ops_read(database.address.prevreg(ea, ins.op_value(ea,0), write=1))) if ins.op_type(ea,0) == 'reg' else ins.op_repr(ea, 0)) for name,ea in result]

    try:
        return '{:s}({:s})'.format(internal.declaration.demangle(function.name(function.by_address(fn))), ','.join(result))
    except:
        pass
    return '{:s}({:s})'.format(internal.declaration.demangle(database.name(fn)), ','.join(result))

def source(ea, *regs):
    '''Return the addresses and which specific operands write to the specified regs'''
    res = []
    for r in regs:
        pea = database.address.prevreg(ea, r, write=1)
        res.append( (pea,tuple(ins.ops_read(pea))) )
    return res

def sourcechain(fn, *args, **kwds):
#    sentinel = kwds.get('types', set(('imm','phrase','addr','void')))
    sentinel = kwds.get('types', set(('imm','addr','void')))

    result = {}
    for ea,opi in source(*args):
        if not function.contains(fn, ea): continue
        opt = tuple(ins.op_type(ea,i) for i in opi)
        for i,t in zip(opi,opt):
            if t in sentinel:
                result.setdefault(ea,set()).add(i)
            elif t in ('reg',):
                result.setdefault(ea,set()).add(i)
                r = ins.op_value(ea,i)
                for a,b in sourcechain(fn, ea, r):
                    map(result.setdefault(a,set()).add, b)
            elif t in ('phrase',):
                result.setdefault(ea,set()).add(i)
                _,(r1,r2,_) = ins.op_value(ea,i)
                for a,b in sourcechain(fn, ea, *tuple(r for r in (r1,r2) if r is not None)):
                    map(result.setdefault(a,set()).add, b)
            elif t in ('imm','addr',):
                result.setdefault(ea,set()).add(i)
            else:
                raise ValueError, (t, ea, i)
            continue
        continue
    return [(ea,result[ea]) for ea in sorted(result.keys())]

# for exposing the ability queueing functions asynchronously..
# which is probably pretty unsafe in IDA, but let's hope.
class queue(object):
    @classmethod
    def __start_ida__(cls):
        if hasattr(cls, 'execute') and not cls.execute.dead:
            logging.warn("{:s}.{:s}.start : Skipping re-instantiation of execution queue. : {!r}".format(__name__, cls.__name__, cls.execute))
            return
        cls.execute = internal.utils.execution()

    @classmethod
    def __stop_ida__(cls):
        if not hasattr(cls, 'execute'):
            logging.warn("{:s}.{:s}.stop : Refusing to release execution queue due to it not being initialized.".format(__name__, cls.__name__))
            return
        cls.execute.release()

    @classmethod
    def __open_database__(cls, idp_modname):
        cls.execute.start()

    @classmethod
    def __close_database__(cls):
        cls.execute.stop()

    @classmethod
    def add(cls, func, *args, **kwds):
        if not cls.execute.running:
            logging.warn("{:s}.{:s}.add : Unable to execute {!r} due to queue not running.".format(__name__, cls.__name__, func))
        return cls.execute.push(func, *args, **kwds)

    @classmethod
    def pop(cls):
        return next(cls.execute)

# for exposing the ability to hook different parts of IDA
class hook(object):
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
        for api in ('idp','idb','ui'):
            res = getattr(cls, api)
            for name in res:
                res.disable(name)
            continue
        return

