import database,function
import sys,logging

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

import idaapi
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

try:
    import PySide.QtGui
except ImportError:
    logging.warn("__module__:%s:Unable to load PySide.QtGui module. Certain UI.* methods might not work.", __name__)

class UI(object):
    '''static class for interacting with IDA's Qt user-interface'''
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

## XXX: would be useful to have a quick wrapper class for interacting with Ida's mark list
##          in the future, this would be abstracted into a arbitrarily sized tree.

def colormarks(color=0x7f007f):
    '''Iterate through all database marks and tag+color their address'''
    # tag and color
    f = set()
    for ea,m in database.marks():
        database.tag(ea, 'mark', m)
        database.color(ea, color)
        try:
            f.add(function.top(ea))
        except ValueError:
            pass
        continue

    # tag the functions too
    for ea in list(f):
        m = function.marks(ea)
        function.tag(ea, 'marks', [ea for ea,_ in m])
    return

def recovermarks():
    '''Utilizing any tag information found in the database, recreate all the database marks.'''
    # collect
    result = []
    for fn,l in database.select('marks'):
        m = set( (l['marks']) if hasattr(l['marks'],'__iter__') else [int(x,16) for x in l['marks'].split(',')] if type(l['marks']) is str else [l['marks']])
        res = [(ea,d['mark']) for ea,d in function.select(fn,'mark')]
        if m != set(a for a,_ in res):
            logging.warning("%x: ignoring cached version of marks due to being out-of-sync with real values : %r : %r", fn, map(hex,m), map(hex,set(a for a,_ in res)))
        result.extend(res)
    result.sort(cmp=lambda x,y: cmp(x[1],y[1]))

    # discovered marks versus database marks
    result = dict(result)
    current = {ea:descr for ea,descr in database.marks()}

    # create tags
    for x,y in result.items():
        if (x not in current) or (current[x] != result[x]):
            if current[x] != result[x]:
                logging.info('%x: database tag is newer than mark description : %r', x, result[x])
            database.mark(x, y)
            continue
        logging.warning('%x: skipping already existing mark : %r', x, current[x])

    # marks that aren't reachable in the database
    for ea in set(current.viewkeys()).difference(result.viewkeys()):
        logging.warning('%x: unreachable mark (global) : %r', ea, current[ea])

    # color them
    colormarks()

def checkmarks():
    '''Output all functions (sys.stdout) containing more than 1 mark.'''
    res = []
    for a,m in database.marks():
        try:
            res.append((function.top(a), a, m))
        except ValueError:
            pass
        continue

    d = list(res)
    d.sort( lambda a,b: cmp(a[0], b[0]) )

    flookup = {}
    for fn,a,m in d:
        try:
            flookup[fn].append((a,m))
        except:
            flookup[fn] = [(a,m)]
        continue

    functions = [ (k,v) for k,v in flookup.items() if len(v) > 1 ]
    if not functions:
        logging.warning('There are no functions available containing multiple marks.')
        return

    for k,v in functions:
        print >>sys.stdout, '%x : in function %s'% (k,function.name(function.byAddress(k)))
        print >>sys.stdout, '\n'.join( ('- %x : %s'%(a,m) for a,m in sorted(v)) )
    return

def above(ea):
    '''Display all the callers of the function at /ea/'''
    tryhard = lambda x: '%s+%x'%(database.name(function.top(x)),x-function.top(x)) if function.within(x) else hex(x) if database.name(x) is None else database.name(x)
    return '\n'.join(map(tryhard,function.up(ea)))

def below(ea):
    '''Display all the functions that the function at /ea/ can call'''
    tryhard = lambda x: '%s+%x'%(database.name(function.top(x)),x-function.top(x)) if function.within(x) else hex(x) if database.name(x) is None else database.name(x)
    return '\n'.join(map(tryhard,function.down(ea)))
