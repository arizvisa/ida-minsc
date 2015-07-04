# some general python modules
import __builtin__,sys,imp
import os,logging,_idaapi as idaapi,ctypes

library = ctypes.WinDLL if os.name == 'nt' else ctypes.CDLL

# grab ida's user directory and remove from path since we use meta_path to locate api modules
root = idaapi.get_user_idadir()
sys.path.remove(root)

class internal_path(object):
    '''Add all files within a subdirectory as submodule to a module'''
    imp = imp

    @staticmethod
    def new_module(name, doc=None, submodules={}):
        '''Create a base module containing the specified submodules'''
        module = type(__import__('__builtin__'))
        result = module(name, doc)
        for name,value in submodules.iteritems():
            setattr(result, name, value)
        return result

    def __init__(self, directory, fullname=None, filter=lambda name:name, doc=None):
        self.path = os.path.realpath(directory)
        self.api = {}
        result = []
        for p in os.listdir(self.path):
            (name,ext) = os.path.splitext(p)
            modulepath,modulename = os.path.join(self.path,p),filter(name)
            if ext == '.py' and modulename:
                self.api[modulename] = self.imp.find_module(name, [self.path])
                result.append((modulename,modulepath))
            continue
        if doc is None:
            doc = '\n'.join('%s -- %s'%(n,p) for n,p in result)
        self.__name__,self.__doc__ = fullname,doc
        return

    def find_module(self, fullname, path=None):
        if self.__name__ and fullname == self.__name__:
            return self
        return self if fullname in self.api.viewkeys() else None

    def load_module(self, fullname):
        if self.__name__:
            submodules = {name : self.imp.load_module(name,*location) for name,location in self.api.iteritems()}
            return self.new_module(self.__name__, self.__doc__, submodules)
        return self.imp.load_module(fullname, *self.api[fullname])

class internal_object(object):
    def __init__(self, name, object):
        self.name,self.object = name,object

    def find_module(self, fullname, path=None):
        return self if path is None and fullname == self.name else None
    def load_module(self, fullname):
        assert fullname == self.name
        return self.object

# ida's native api
sys.meta_path.append( internal_object('ida',library('ida.wll')) )

# private api
sys.meta_path.append( internal_path(os.path.join(root,'base'), 'internal', lambda s: s[1:] if s.startswith('_') else None) )

# public api
sys.meta_path.append( internal_path(os.path.join(root,'base'), filter=lambda s: None if s.startswith('_') else s) )
sys.meta_path.append( internal_path(os.path.join(root,'misc')) )

# user and application api's
for n in ('custom','app'):
    sys.meta_path.append( internal_path(os.path.join(root,n), n) )

# temporarily root namespace
__root__ = imp.load_source('__root__', os.path.join(root,'__root__.py'))

# empty out idapython's namespace
map(globals().pop, filter(lambda(_):not _.startswith('_'),globals().copy().keys()))

# re-populate with a default namespace and empty out our variable
globals().update(__root__.__dict__)
globals().pop('__root__')

# try and execute our user's idapythonrc.py
try:
    try:
        # execute user's .pythonrc and .idapythonrc in one go
        if __import__('user').home:
            execfile(__import__('os').path.join(__import__('user').home, 'idapythonrc.py'))

    except ImportError:
        # otherwise try to figure it out without tainting the namespace
        if __import__('os').getenv('HOME'):
            execfile(__import__('os').path.join(__import__('os').getenv('HOME'), 'idapythonrc.py'))
        elif __import__('os').getenv('USERPROFILE'):
            execfile(__import__('os').path.join(__import__('os').getenv('USERPROFILE'), 'idapythonrc.py'))
        else:
            raise OSError('Unable to figure out home directory')
        pass

except IOError:
    __import__('logging').warn('No idapythonrc.py file found in home directory')

except Exception, e:
    print 'warning: Unexpected exception %s raised'% repr(e)
    __import__('traceback').print_exc()
