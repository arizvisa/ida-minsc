"""
Declaration module (internal)

This module contains some tools used for extracting information out of
function and type declarations.

TODO: Implement parsers for some of the C++ symbol manglers in order to
      query them for specific attributes or type information.
"""

import function as fn, database as db
import internal, idaapi

### c declaration stuff
def function(ea):
    '''Returns the C function declaration at the address `ea`.'''
    res = idaapi.idc_get_type(ea)
    if res is None:
        raise internal.exceptions.MissingTypeOrAttribute("The function {:x} does not have a declaration.".format(ea))
    return res

def arguments(ea):
    '''Returns an array of all of the arguments within the prototype of the function at `ea`.'''
    decl = function(ea)
    args = decl[ decl.index('(')+1: decl.rindex(')') ]
    return [ arg.strip() for arg in args.split(',')]

def size(string):
    '''Returns the size of a type described by a C declaration in `string`.'''
    string = string.strip()
    if string.lower() == 'void':
        return 0
    elif string.startswith('class') and string.endswith('&'):
        res = idaapi.idc_parse_decl(idaapi.cvar.idati, 'void*;', 0)
    else:
        res = idaapi.idc_parse_decl(idaapi.cvar.idati, string if string.endswith(';') else string+';', 0)

    if res is None:
        raise internal.exceptions.DisassemblerError("Unable to parse the specified C declaration ({!r}).".format(string))
    _, type, _ = res
    return idaapi.get_type_size0(idaapi.cvar.idati, type)

def demangle(string):
    '''Given a mangled C++ `string`, demangle it back into a human-readable symbol.'''
    return extract.declaration(string)

def mangledQ(string):
    '''Return true if the provided `string` has been mangled.'''
    return any(string.startswith(n) for n in ('?', '__'))

## examples to test below code with
#"??_U@YAPAXI@Z"
#"?_BADOFF_func@std@@YAABJXZ"
#"??$_Div@N@?$_Complex_base@NU_C_double_complex@@@std@@IAEXABV?$complex@N@1@@Z"
#"??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV01@PBX@Z"
#"??1?$basic_ostream@DU?$char_traits@D@std@@@std@@UAE@XZ"
#"??_F?$basic_stringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QAEXXZ"
#"??1type_info@@UAE@XZ"
#"sub_784B543B"
#"?_Atexit@@YAXP6AXXZ@Z"
#"?__ArrayUnwind@@YGXPAXIHP6EX0@Z@Z"

# FIXME: this code is so hacky, that i need unit-tests for it...which should be properly fixed.
#        1] If I write a parser, I can easily split out these components. (proper fix)
#        2] If I use IDA's metadata to figure out each type, I can use those strings to cull them out of the declaration. (hackish)
#        3] I could use completely unmaintainable nfa-based pattern matching. (regexes whee)
#        4] I could continue to use string operations to cut parts out...except that they're unable to solve this problem
#           due to the need to keep a recursive state somewhere in order to associate types with. (current)
class extract:
    @staticmethod
    def declaration(string):
        res = idaapi.demangle_name(string, idaapi.cvar.inf.long_demnames)
        return string if res is None else res

    @staticmethod
    def convention(string):
        types = set(('__cdecl', '__stdcall', '__thiscall', '__fastcall'))
        res = string.split(' ')
        return res[0]

    @staticmethod
    def fullname(string):
        decl = extract.declaration(string)
        return decl[:decl.find('(')].split(' ', 3)[-1] if any(n in decl for n in ('(', ' ')) else decl

    @staticmethod
    def name(string):
        fn = extract.fullname(string)
        return fn.rsplit(':', 2)[-1] if ':' in fn else fn

    @staticmethod
    def arguments(string):
        decl = extract.declaration(string)
        return map(str.strip, decl[decl.index('(')+1:decl.find(')')].split(',')) if '(' in decl else []

    @staticmethod
    def result(string):
        decl = extract.declaration(string)
        decl = decl[:decl.find('(')].rsplit(' ', 1)[0]
        return decl.split(':', 1)[1].strip() if ':' in decl else decl.strip()

    @staticmethod
    def scope(string):
        decl = extract.declaration(string)
        decl = decl[:decl.find('(')].rsplit(' ', 1)[0]
        return decl.split(':', 1)[0].strip() if ':' in decl else ''
