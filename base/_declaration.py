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

def size(string):
    '''returns the size of a c declaration'''
    string = string.strip()
    if string.lower() == 'void':
        return 0
    elif string.startswith('class') and string.endswith('&'):
        result = idc.ParseType('void*;', 0)
    else:
        result = idc.ParseType(string if string.endswith(';') else string+';', 0)

    if result is None:
        raise TypeError,'Unable to parse C declaration : %r'% str
    _,type,_ = result
    return idc.SizeOf(type)

def demangle(string):
    '''demangle's a symbol to a human-decipherable string'''
    return extract.declaration(string)

class extract:
    @staticmethod
    def declaration(string):
        result = idc.Demangle(string, idc.GetLongPrm(idc.INF_LONG_DN))
        return string if result is None else result

    @staticmethod
    def name(string):
        result = extract.declaration(string)
        return result[:result.find('(')].rsplit(' ',1)[-1]

    @staticmethod
    def arguments(string):
        result = extract.declaration(string)
        return map(str.strip,result[result.index('(')+1:result.find(')')].split(','))

    @staticmethod
    def result(string):
        result = extract.declaration(string)
        result = result[:result.find('(')].rsplit(' ',1)[0]
        return result.split(':',1)[1].strip() if ':' in result else result.strip()

    @staticmethod
    def scope(string):
        result = extract.declaration(string)
        result = result[:result.find('(')].rsplit(' ',1)[0]
        return result.split(':',1)[0].strip() if ':' in result else ''
