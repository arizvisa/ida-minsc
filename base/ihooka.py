import os,ihooks,idc

'''
this hooks python 'import' and exports the functions a module provides to the ida log window.

TODO:
    write a function for enumerating all the modules.functions available
'''
## python-specific types
class dummy(object):
    def method(self): pass
instancemethod = type(dummy.method)
del(dummy)
function = type(lambda:False)
code = type(eval('lambda:False').func_code)
builtin = type(zip)

## wrappers around common output functions so that it feels like C
## as i'm bored of python lately
def log(string, *argv):
    '''idc.Message(formatstring, ...)'''
    #XXX: output to a logfile
    return idc.Message('>' + string% argv + '\n')

def getCodeParameters(code):
    res = list(code.co_varnames)
    arguments = res[:code.co_argcount]
    return (code.co_name, arguments)

def getCallablePrototypeComponents(callableobject):
    res = callableobject
    defaults = None

    if type(res) is function:
        name, parameters = getCodeParameters(res.func_code)
        defaults = res.func_defaults
        assert name == res.func_name

    elif type(res) is instancemethod:
        name, parameters = getCallablePrototypeComponents(res.im_func)
        name = '%s.%s'% ( res.im_class.__name__, name )
        return name, parameters

    elif type(res) is builtin:
        name, parameters = (res.__name__, ("..."))

    else:
        raise TypeError, type(res)

    res = parameters
    if defaults:
        defaults = list(defaults)
        res = ["%s"% p for p in parameters[:-len(defaults)]]
        res += ["%s=%s"% (p, d) for p,d in zip(parameters[-len(defaults):], defaults)]
    return name, res

def indent(string, spaces=4):
    '''indents a string by the specified number of spaces'''
    indentation = ' '*spaces
    return '\n'.join([indentation+x for x in string.split('\n')])

def prototype(object):
    '''will return a printable prototype of a function/method'''
    # TODO: need to implement *args, and **kwds support too
    assert callable(object)
    name, parameters = getCallablePrototypeComponents(object)
    return '%s(%s)'% (name, ', '.join(parameters))

def head(string, lines=5):
    return '\n'.join(string.split('\n')[:lines])

def documentFunctions(list):
    functiondesc =  lambda n: '%s.%s'% (n.__module__,prototype(n))

    def iwantmultilinelambdasorconditionalassignmentsinoneline(object):
        modulename = object.__module__

        # XXX: we only care about 1 level worth of modulename
        #      this could break formatting. oh well.
        try:
            idx = modulename.rindex('.')
            modulename = modulename[idx+1:]
        except ValueError:
            pass
        res = '%s.%s'% (modulename,prototype(object))

        doc = object.__doc__
        if doc and head(doc, 1).strip():
            res += ' -> ' + doc
        return res
        
    return [iwantmultilinelambdasorconditionalassignmentsinoneline(n) for n in list if type(n) is type(documentFunctions)]

def dumpModule(module, file, filename, info):

    try:
        exports = module.EXPORT
        exports = [getattr(module, n) for n in exports]
        log("loaded module (%s)"% filename)

    except AttributeError:
        exports = [getattr(module, n) for n in dir(module)]
        exports = [n for n in exports if type(n) is type(dumpModule)]
        exports = [n for n in exports if n.__module__ == module.__name__]
        log("loaded untagged module '%s' (%s)", module, filename)

    if module.__doc__:
        log(module.__doc__)
    
    # try REALLY hard to output useful stuff
    try:
        log("    providing ->\n%s", indent('\n'.join( documentFunctions(exports) ), 8))

    except Exception, e:
        log("    exception %s raised during provide() output", repr(e))

## loader import
# mostly copied from here-> http://quixote.python.ca/quixote.dev/quixote/ptl/ptl_import.py
class moduleloader(ihooks.ModuleLoader):
    def load_module(self, module, stuff):
        file, filename, info = stuff

        res = ihooks.ModuleLoader.load_module(self, module, stuff)

        if 'IDA Pro' not in filename.split(os.sep): #XXX: heh...
            return res

        if res.__name__.startswith('__root__'):
            return res

        dumpModule(res, file, filename, info)
        return res

importer = ihooks.ModuleImporter(moduleloader())
ihooks.install(importer)
