# some general python modules
import sys,os,logging,imp
import idaapi

# grab ida's user directory and add to path
root = idaapi.get_user_idadir()
sys.path = list(set(sys.path)) + [root]

class __base__(object):
    '''Context related modules'''
    base = os.path.join(root, 'base')
    imp = imp

    _api = [(os.path.splitext(p)[0],os.path.realpath(os.path.join(base,p))) for p in os.listdir(base) if not os.path.basename(p).startswith('_') and os.path.splitext(p)[1] == '.py']
    _cache = [imp.find_module(name,[base]) for name,_ in _api]
    assert all(p1 == p2 for (n1,p1),(_,p2,_) in zip(_api,_cache))

    cache = dict((n,c) for (n,_),c in zip(_api,_cache))

    @classmethod
    def find_module(cls, fullname, path=None):
        return cls if path is None and fullname in cls.cache.viewkeys() else None
    @classmethod
    def load_module(cls, fullname):
        if fullname not in cls.cache.viewkeys():
            raise ImportError, fullname
        return __import__('sys').modules.setdefault(fullname, cls.imp.load_module(fullname, *cls.cache[fullname]))

class __submodule__(object):
    '''A lazy-loaded module named according to the subdirectory the modules are in'''
    imp = imp
    @staticmethod
    def get_module_name(path):
        return os.path.splitext(os.path.basename(path))[0]
    def __init__(self, path):
        assert os.path.isdir(path), '%s not a valid directory'% path
        rp = os.path.abspath(path)
        name = os.path.split(rp)[1]
        files = [os.path.join(rp,_) for _ in sorted(os.listdir(rp)) if os.path.splitext(_)[1] == '.py' and not _.startswith('_')]
        submodules = dict(self.import_module(p) for p in files)
        cache = {}

        imp = self.imp
        def __getattr__(self, name):
            if name in submodules:
                if name in cache:
                    return cache[name]
                res = imp.load_module(name,*submodules[name])
                self.__doc__ = self.__doc__ or '' + getattr(res,'__doc__','')
                return res
            return object.__getattribute__(self, name)

        # create lazy-loader module
        module = self.new_module(name,__getattribute__=__getattr__)
        for k in submodules.viewkeys():
            setattr(module, k, type(module))
        setattr(module, '__doc__', '%s - Modules in sub-directory %s'%(name, rp))

        self.name,self.module = name,module

    @classmethod
    def import_module(cls, path):
        name = cls.get_module_name(path)
        res = cls.imp.find_module(name, [os.path.dirname(path)])
        _,p,_ = res
        if p != path:
            raise ImportError, '%s != %s'% (p,path)
        return name,res

    @staticmethod
    def new_module(name, **attrs):
        __builtin__ = __import__('__builtin__')
        m = type(__builtin__)
        return type(name, (m,), attrs)(name)
        
    def find_module(self, fullname, path=None):
        return self if fullname == self.name else None

    def load_module(self, fullname):
        if fullname != self.name:
            raise ImportError, 'Unexpected module name %s (expected %s)'% (fullname, self.name)
        return __import__('sys').modules.setdefault(self.name, self.module)

# add import hook for internal api
sys.meta_path.append(__base__)

# add custom subdirs to the search path
for p in (_ for _ in os.listdir(root) if os.path.isdir(os.path.join(root,_)) and not _.startswith('.')):
    path = os.path.join(root, p)
    if path == __base__.base:
        continue
    #sys.meta_path.append(__submodule__(path))
    sys.path.append(path)

# empty out idapython's namespace
import __builtin__
[__builtin__.globals().pop(_) for _ in __builtin__.globals().copy() if not _.startswith('_')]

# re-populate with a default namespace
from __root__ import *

# try and execute our user's idapythonrc.py
try:
    if os.getenv('HOME'):
        execfile(os.path.join(os.getenv('HOME'), 'idapythonrc.py'))
    elif os.getenv('USERPROFILE'):
        execfile(os.path.join(os.getenv('USERPROFILE'), 'idapythonrc.py'))
    else:
        raise OSError('Unable to figure out home directory')
    pass
except IOError:
    logging.warn('No idapythonrc.py file found in home directory')

except Exception, e:
    print 'warning: Unexpected exception %s raised'% repr(e)
    import traceback
    traceback.print_exc()
