import function as fn,database as db
import idaapi

### c declaration stuff
def function(ea):
    '''returns the C function declaration at given address'''
    result = idaapi.idc_get_type(ea)
    if result is None:
        raise ValueError('function {:x} does not have a declaration'.format(ea))
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
        result = idaapi.idc_parse_decl(idaapi.cvar.idati, 'void*;', 0)
    else:
        result = idaapi.idc_parse_decl(idaapi.cvar.idati, string if string.endswith(';') else string+';', 0)

    if result is None:
        raise TypeError('Unable to parse C declaration : {!r}'.format(string))
    _,type,_ = result
    return idaapi.get_type_size0(idaapi.cvar.idati, type)

def demangle(string):
    '''demangle's a symbol to a human-decipherable string'''
    return extract.declaration(string)

# examples to test below code with
"??_U@YAPAXI@Z"
"?_BADOFF_func@std@@YAABJXZ"
"??$_Div@N@?$_Complex_base@NU_C_double_complex@@@std@@IAEXABV?$complex@N@1@@Z"
"??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV01@PBX@Z"
"??1?$basic_ostream@DU?$char_traits@D@std@@@std@@UAE@XZ"
"??_F?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEXXZ"
"??1type_info@@UAE@XZ"
"sub_784B543B"
"?_Atexit@@YAXP6AXXZ@Z"
"?__ArrayUnwind@@YGXPAXIHP6EX0@Z@Z"

# FIXME: this code is so hacky, that i need unit-tests for it...which should be properly fixed.
#        1] If I write a parser, I can easily split out these components. (proper fix)
#        2] If I use IDA's metadata to figure out each type, I can use those strings to cull them out of the declaration. (hackish)
#        3] I could use properly unmaintainable nfa-based pattern matching. (regex)
#        4] I could continue to use string operations to cut parts out...except that they're unable to solve this problem
#           due to the need to keep a recursive state somewhere in order to associate types with. (current)
class extract:
    @staticmethod
    def declaration(string):
        result = idaapi.demangle_name(string, idaapi.cvar.inf.long_demnames)
        return string if result is None else result

    @staticmethod
    def convention(string):
        types = set(('__cdecl', '__stdcall', '__thiscall', '__fastcall'))
        result = string.split(' ')

    @staticmethod
    def fullname(string):
        result = extract.declaration(string)
        return result[:result.find('(')].split(' ',3)[-1]

    @staticmethod
    def name(string):
        result = extract.fullname(string)
        return result.rsplit(':',2)[-1]

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
