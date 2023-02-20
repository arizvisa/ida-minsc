"""
Declaration module (internal)

This module contains some tools used for extracting information out of
function and type declarations.

TODO: Implement parsers for some of the C++ symbol manglers in order to
      query them for specific attributes or type information.
"""
import string as _string

import internal, idaapi
from internal import utils, exceptions, types

### c declaration stuff
def function(ea):
    '''Returns the C function declaration at the address `ea`.'''
    res = idaapi.idc_get_type(ea)
    if res is None:
        raise exceptions.MissingTypeOrAttribute(u"The function {:x} does not have a declaration.".format(ea))
    return res

def arguments(ea):
    '''Returns an array of all of the arguments within the prototype of the function at `ea`.'''
    decl = function(ea)
    args = decl[ decl.index('(') + 1 : decl.rindex(')') ]
    return [ arg.strip() for arg in args.split(',')]

def size(string):
    '''Returns the size of a type described by a C declaration in `string`.'''
    til = idaapi.cvar.idati if idaapi.__version__ < 7.0 else idaapi.get_idati()

    string = string.strip()
    if string.lower() == 'void':
        return 0
    elif string.startswith('class') and string.endswith('&'):
        res = idaapi.idc_parse_decl(til, 'void*;', 0)
    else:
        semicoloned = string if string.endswith(';') else "{:s};".format(string)
        res = idaapi.idc_parse_decl(til, utils.string.to(semicoloned), 0)

    if res is None:
        raise exceptions.DisassemblerError(u"Unable to parse the specified C declaration (\"{:s}\").".format(utils.string.escape(string, '"')))
    _, type, _ = res
    f = idaapi.get_type_size0 if idaapi.__version__ < 6.8 else idaapi.calc_type_size
    return f(til, type)

@utils.string.decorate_arguments('string')
def demangle(string):
    '''Given a mangled C++ `string`, demangle it back into a human-readable symbol.'''
    if idaapi.__version__ < 7.0:
        res = idaapi.demangle_name(utils.string.to(string), idaapi.cvar.inf.long_demnames)
    else:
        res = idaapi.demangle_name(utils.string.to(string), idaapi.cvar.inf.long_demnames, idaapi.DQT_FULL)
    return string if res is None else utils.string.of(res)

def mangledQ(string):
    '''Return true if the provided `string` has been mangled.'''
    return any(string.startswith(item) for item in ['?', '__'])

@utils.string.decorate_arguments('info')
def parse(info):
    '''Parse the string `info` into an ``idaapi.tinfo_t``.'''
    if idaapi.__version__ < 7.0:
        til, ti = idaapi.cvar.idati, idaapi.tinfo_t(),
    else:
        til, ti = idaapi.get_idati(), idaapi.tinfo_t(),

    # Convert info to a string if it's a tinfo_t
    info_s = "{!s}".format(info) if isinstance(info, idaapi.tinfo_t) else info

    # Firstly we need to ';'-terminate the type the user provided in order
    # for IDA's parser to understand it.
    terminated = info_s if info_s.endswith(';') else "{:s};".format(info_s)

    # Ask IDA to parse this into a tinfo_t for us. We pass the silent flag so
    # that we're responsible for raising an exception if there's a parsing
    # error of some sort. If it succeeds, then we can return our typeinfo.
    # Otherwise we return None because of the inability to parse it.
    if idaapi.__version__ < 6.9:
        return None if idaapi.parse_decl2(til, terminated, None, ti, idaapi.PT_SIL) is None else ti
    elif idaapi.__version__ < 7.0:
        return None if idaapi.parse_decl2(til, terminated, ti, idaapi.PT_SIL) is None else ti
    return None if idaapi.parse_decl(ti, til, terminated, idaapi.PT_SIL) is None else ti

def string(ti):
    prefix = ''
    name, indent = '', 4
    cmt, cindent = '', 4
    flags = idaapi.PRTYPE_DEF | idaapi.PRTYPE_MULTI
    return idaapi.print_tinfo(prefix, indent, cindent, flags, ti, name, cmt)

def unmangle_name(name):
    '''Return the function name from a prototype to be used for rendered an ``idaapi.tino_t``.'''

    # Check to see if our name is demangled. If not, then we can just return it.
    demangled = demangle(name)
    if not name or demangled == name:
        return demangled

    # If so, then we need to do some trickery to extract the name.
    has_parameters = any(item in demangled for item in '()')
    noparameters = demangled[:demangled.find('(')] if has_parameters else demangled

    # Strip out all templates
    notemplates, count = '', 0
    for item in noparameters:
        if item in '<>':
            count += +1 if item in '<' else -1
        elif count == 0:
            notemplates += item
        continue

    # Now we need to remove the calling convention as it should be in the typeinfo.
    items = notemplates.split(' ')
    conventions = {'__cdecl', '__stdcall', '__fastcall', '__thiscall', '__pascal', '__usercall', '__userpurge'}
    try:
        ccindex = next(idx for idx, item in enumerate(items) if any(item.endswith(cc) for cc in conventions))
        items = items[1 + ccindex:]

    # We couldn't find a calling convention, so there's no real work to do.
    except StopIteration:
        items = items[:]

    # Strip out any backticked components, operators, and other weirdness.
    foperatorQ = lambda string: string.startswith('operator') and any(string.endswith(invalid) for invalid in _string.punctuation)
    joined = ' '.join(items)
    if '::' in joined:
        components = joined.split('::')
        components = (item for item in components if not item.startswith('`'))
        components = ('operator' if foperatorQ(item) else item for item in components)
        joined = '::'.join(components)

    # Check to see if this is some operator of some kind.
    if joined.count(' ') > 0 and joined.rsplit(' ', 2)[-2].endswith('operator'):
        return '_'.join(joined.rsplit(' ', 2)[-2:])

    # Now we can drop everything before the last space, and then return it.
    return joined.rsplit(' ', 1)[-1]

def unmangle_arguments(ea, info):
    if not info.present():
        raise ValueError(info)

    # Grab the parameters from the idc type as it includes more information
    parameters = extract.arguments("{!s}".format(idaapi.idc_get_type(ea))) or extract.arguments("{!s}".format(info))
    param_s = parameters.lstrip('(').rstrip(')')

    index, indices, iterable = 0, [], ((idx, item) for idx, item in enumerate(param_s))
    for argi in range(info.get_nargs()):
        arg = info.get_nth_arg(argi)
        arg_s = "{!s}".format(arg)

        index, ch = next(iterable, (1 + index, ','))
        while ch in ' ':
            index, ch = next(iterable)

        while ch != ',':
            for item in arg_s:
                index, ch = next(iterable)
                if ch != item: break

            count = 0
            while ch != ',' or count > 0:
                index, ch = next(iterable, (1 + index, ','))
                if ch in '()':
                    count += -1 if ch in ')' else +1
                continue

            indices.append(index)

    pos, res = 0, []
    for argi, index in enumerate(indices):
        arg = info.get_nth_arg(argi)
        arg_s = "{!s}".format(arg)

        item = param_s[pos : index].strip()
        pos = 1 + index

        t, name = item[:len(arg_s)], item[len(arg_s):]
        res.append((t.strip(), name.strip()))
    return res

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
        return demangle(string)

    @staticmethod
    def convention(string):
        types = {'__cdecl', '__stdcall', '__thiscall', '__fastcall'}
        res = string.split(' ')
        return res[0]

    @staticmethod
    def fullname(string):
        decl = extract.declaration(string)
        return decl[:decl.find('(')].split(' ', 3)[-1] if any(item in decl for item in ['(', ' ']) else decl

    @staticmethod
    def name(string):
        fn = extract.fullname(string)
        return fn.rsplit(':', 2)[-1] if ':' in fn else fn

    @staticmethod
    def arguments(string):
        res, count = '', 0
        for item in string[::-1]:
            if item in '()':
                count += +1 if item in ')' else -1
                res += item
            elif count > 0:
                res += item
            elif count == 0:
                break
            continue
        return str().join(reversed(res))

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

class nested(object):
    """
    This namespace contains basic utilities for processing a string
    containing a nested set of characters. This intends to allow one
    to either select or modify the nested string in a depth-first order.

    Although the functions declared within can be consolidated into
    a single and individual function, it is broken down into multiple
    components for readability purposes and to allow another class
    to inherit and modify its functionality.
    """

    @classmethod
    def indices(cls, string, characters):
        '''Yield each index of the matching `characters` from the given `string`.'''
        iterable = (string.find(character) for character in characters)
        current, index = 0, min([index for index in iterable if 0 <= index] or [-1])
        while 0 <= index:
            yield current + index, 1
            current, string = current + 1 + index, string[1 + index:]
            iterable = [string.find(character) for character in characters]
            index = min([index for index in iterable if 0 <= index] or [-1])
        return

    @classmethod
    def parse(cls, string, pairs):
        '''Return a list of ranges, a tree, and a list of indices for the errors when parsing the given character `pairs` out of `string`.'''
        open, close, openers = {pair[0] for pair in pairs}, {pair[1] for pair in pairs}, {pair[-1] : pair[0] for pair in pairs}
        stack, errors, tree, order = [], [], {}, []
        for index, length in cls.indices(string, [character for character in itertools.chain(*pairs)]):
            if string[index] in open:
                stack.append(index)
            elif string[index] in close and stack and string[stack[-1]] == openers[string[index]]:
                #segment = stack.pop(), index + 1
                segment = stack.pop(), index + length
                layer = tree.setdefault(stack[-1] if stack else None, [])
                order.append(segment), layer.append(segment)
            else:
                errors.append(index)
            continue
        return order, tree, stack + errors

    @classmethod
    def verify(cls, tree, ordered, index=None):
        '''Verify a `tree` of character ranges against a mutable `ordered` list of ranges.'''
        ok = True
        for item in tree.get(index, []):
            start, stop = item
            if start in tree:
                ok = ok and cls.verify(tree, ordered, start)
            slice = ordered.pop(0)
            ok = ok and item == slice
        return ok

    # XXX: this is not really an augmented tree, but i needed a verb.
    @classmethod
    def augment(cls, tree):
        '''Convert the given `tree` of ranges into a tree of sizes that can be used to modify the string associated with the original tree.'''
        result = {}
        for index, items in tree.items():
            skip, new_items = index or 0, result.setdefault(index, [])
            for left, right in items:
                skip, size = left - skip, right - left
                new_items.append((skip, left, size))
                skip = right
            continue
        return result

    #def modify(string, augmented, index=None):
    #    result, pos = [], 0
    #    for skip, key, size in augmented.get(index, []):
    #        skipped, pos = string[pos : pos + skip], pos + skip

    #        original = string[pos : pos + size]
    #        if key in tree:
    #            modified = modify(original, augmented, key)
    #            replaced = modified[:]
    #        else:
    #            replaced = original[:]

    #        _, pos = result.extend([skipped, replaced]), pos + size
    #    result.append(string[pos:])
    #    return ''.join(result)

    @classmethod
    def process(cls, callable, string, augmented, index=None):
        '''Process the nested contents of `string` using the given `allable` and the sizes specified by the tree in `augmented`.'''
        result, position = [], 0
        for skip, key, size in augmented.get(index, []):
            skipped, position = string[position : position + skip], position + skip
            original = string[position : position + size]
            modified = callable(cls.process(callable, original, augmented, key) if key in augmented else original)
            _, position = result.extend([skipped, modified]), position + size
        result.append(string[position:])
        return ''.join(result)

    @classmethod
    def last(cls, string, characters):
        '''Return the range of nested `characters` at the end of the given `string`.'''
        reversed = string[::-1]
        start, stop, counter = reversed.find(characters[1]), -1, 0
        iterable = cls.indices(reversed, characters) if start >= 0 else []

        # Iterate through all of our indices that were found.
        for index, length in iterable:
            character = reversed[index : index + length]
            if character == characters[1]:
                counter = counter + 1
            elif character == characters[0] and counter > 1:
                counter = counter - 1
            elif character == characters[0] and counter:
                counter, stop = 0, index + len(characters[0])
            if not counter:
                break
            continue

        # If the counter is not 0 or we didn't find any trailers, then we return equal
        # values. The only thing left to do is to with the result is to invert it.
        start, stop = (start, start) if stop <= start or counter else (start, stop)
        corrected = (0 if index < 0 else index for index in [stop, start])
        return tuple(len(string) - index for index in corrected)

    @classmethod
    def first(cls, string, characters):
        '''Return the range of nested `characters` at the beginning of the given `string`.'''
        start, stop, counter = string.find(characters[0]), -1, 0
        iterable = cls.indices(string, characters) if start >= 0 else []
        for index, length in iterable:
            character = string[index : index + length]
            if character == characters[0]:
                counter = counter + 1
            elif character == characters[1] and counter > 1:
                counter = counter - 1
            elif character == characters[1] and counter:
                counter, stop = 0, index + len(characters[1])
            if not counter:
                break
            continue

        # If the counter is not 0 or we didn't find any trailers, then we return equal
        # values. The only thing left to do is to with the result is to invert it.
        start, stop = (start, start) if stop <= start or counter else (start, stop)
        return tuple(0 if index < 0 else index for index in [start, stop])

    @classmethod
    def coroutine(cls, string, tokens):
        '''Return a coroutine that yields each of the components nested by `tokens` for the given `string` while yielding the final string at the end.'''

        # This closure is pretty much the "process" classmethod refactored into a
        # coroutine so that the user does not need to create their own closure to
        # process the nested characters within the string.
        def closure(Fappend, string, augmented, index=None):
            position = 0
            for skip, key, size in augmented.get(index, []):
                skipped, position = string[position : position + skip], position + skip
                original = string[position : position + size]

                # Make a list that we'll use to gather results from processing our
                # string. If the key we got from iterating through "augmented" exists,
                # then we'll need to recurse to collect any modifications from the user.
                processed = []
                if key in tree:
                    coroutine = closure(processed.append, original, augmented, key)
                    process, changed = True, next(coroutine, original)

                # Otherwise we don't need to recurse or process anything, so append our
                # original slice to our "processed" list so we can join it at the end.
                else:
                    processed.append(original)
                    process, changed = False, original

                # While we're "supposed" to process the original, continue forever
                # consuming whatever was sent to us and forwarding that result directly
                # to the coroutine to add items changed by the user to our collection.
                try:
                    while process:
                        changed = coroutine.send((yield changed))
                except StopIteration:
                    pass

                # Now we can take the items that we collected and join it into a string.
                finally:
                    modified = (yield ''.join(processed))

                # Append the characters we skipped and the modification we were sent
                # using the callable we were given in the first parameter.
                [Fappend(component) for component in [skipped, modified]]
                position = position + size

            # Then we can add the rest of the string and be done with it.
            Fappend(string[position:])

        # First we need to parse our string for the ranges we'll use to process
        # it, and then convert our tree from ranges into sizes.
        ordered, tree, errors = cls.parse(string, tokens)
        augmented = cls.augment(tree)

        #assert(verify(tree, ordered) and len(ordered) == 0)
        #assert(sum(string.count(token) for token in tokens) == sum(map(len, tokens)) * sum(map(len, tree.values())) + len(errors))

        # Our closure uses lists, so we need to gather our results into one
        # so that we can join it into a string at the end and yield it.
        result = []
        coro = closure(result.append, string, augmented)
        try:
            component = next(coro)
            while True:
                component = coro.send((yield component))
        except StopIteration:
            pass

        # Now we should have our transformed result and just need to
        # join it back into a string before we yield it to the caller.
        yield ''.join(result)

class token(nested):
    """
    This namespace contains basic utilities for processing a string
    containing a nested set of tokens and is based on the recently
    declared ``nested`` class. This class allows one to select or
    modify the nested parts of a string in a depth-first order.
    """

    @classmethod
    def indices(cls, string, tokens):
        '''Yield each index and corresponding length for the matching `tokens` from `string`.'''
        current, iterable = 0, ((string.find(token), len(token)) for token in tokens)
        index, skip = min([(index, length) for index, length in iterable if 0 <= index] or [(-1, 1)])
        while 0 <= index:
            yield current + index, skip
            current, string = current + skip + index, string[skip + index:]
            iterable = ((string.find(token), len(token)) for token in tokens)
            index, skip = min([(index, length) for index, length in iterable if 0 <= index] or [(-1, 1)])
        return

    @classmethod
    def parse(cls, string, tokens):
        '''Return a list of ranges, a tree, and a list of indices for the errors when parsing the given `tokens` out of `string`.'''
        stack, tree, order, errors = [], {}, [], []
        for index, length in cls.indices(string, tokens):
            token = string[index : index + length]
            if token == tokens[0]:
                stack.append(index)
            elif stack:
                assert(token == tokens[1])
                segment = stack.pop(), index + length
                layer = tree.setdefault(stack[-1] if stack else None, [])
                order.append(segment), layer.append(segment)
            else:
                errors.append((index, index + length))
            continue
        return order, tree, stack + errors
