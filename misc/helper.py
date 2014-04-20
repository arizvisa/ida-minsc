import database,function

class remote(object):
    '''For poor folk without a dbgeng'''
    def __init__(self, remotebaseaddress, localbaseaddress=None):
        if localbaseaddress is None:
            localbaseaddress = database.baseaddress()
        self.lbase = localbaseaddress
        self.rbase = remotebaseaddress

    def get(self, addr):
        offset = addr - self.rbase
        return offset + self.lbase

    def put(self, ea):
        offset = ea - self.lbase
        return offset + self.rbase

    def go(self, ea):
        database.go( self.get(ea) )

import idaapi,sip
class InputBox(idaapi.PluginForm):
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        
    def OnClose(self, form):
        pass

    def Show(self, caption, options=0):
        return super(InputBox,self).Show(caption, options)


### locate window under current cursor position
### pop-up a menu item
### pop-up a form/messagebox
### another item menu to toolbar
### find the QAction associated with a command (or keypress)

import PySide.QtGui,idaapi
class UI(object):
    @classmethod
    def application(cls):
        return PySide.QtGui.QApplication.instance()

    @classmethod
    def clipboard(cls):
        return cls.application().clipboard()

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
    
    # FIXME: add some support for manipulating menus
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

    class current(object):
        """Current ida state"""
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
            return idaapi.get_func(ea)
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

#class MenuItem(QtGui.

#import symath
#from symath.directed import DirectedGraph

#class navigation(object):
#    pass

def colormarks():
    # tag and color
    f = set()
    for ea,m in database.marks():
        database.tag(ea, 'mark', m)
        database.color(ea, 0x7f007f)
        try:
            f.add(function.top(ea))
        except ValueError:
            pass
        continue

    # tag the functions too
    for ea in list(f):
        m = function.marks(ea)
        database.tag(ea, 'marks', ','.join([hex(a) for a,b in m]))
    return
