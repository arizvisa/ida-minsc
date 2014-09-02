import idc
import function as fn,database as db

### c declaration stuff
def function(ea):
    '''returns the C function declaration at given address'''
    result = idc.GetType(ea)
    if result is None:
        raise ValueError('function %x does not have a declaration'% ea)
    return result

def arguments(ea):
    '''returns an array of all the function's C arguments'''
    decl = function(ea)
    args = decl[ decl.index('(')+1: decl.rindex(')') ]
    result = [ x.strip() for x in args.split(',')]
    return result

def size(str):
    '''returns the size of a c declaration'''
    if not str.endswith(';'):
        str = str + ';'
    result = idc.ParseType(str, 0)
    if result is None:
        raise TypeError('Unable to parse C declaration %s'% repr(str))
    _,type,_ = result
    return idc.SizeOf(type)

def demangle(str):
    '''demangle's a symbol to a human-decipherable string'''
    result = idc.Demangle(str, idc.GetLongPrm(idc.INF_LONG_DN))
    return str if result is None else result

