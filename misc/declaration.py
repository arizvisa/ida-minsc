"""
Declaration module (internal)

This module contains some tools used for extracting information out of
function and type declarations.

TODO: Implement parsers for some of the C++ symbol manglers in order to
      query them for specific attributes or type information.
"""
import functools, operator, itertools, string as _string

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

class extract(object):
    """
    This namespace is responsible for extracting specific parts of an
    unmangled C++ name using the tree that has been parsed and created
    by either the `nested` or `token` namespace. The functions within
    the namespace do not return strings directly, but rather a tuple
    that contains the slice of the string that is being acted upon.
    """
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

    ## XXX: all of the `extract` classmethods defined before this are mad ancient,
    ##      and more importantly can be treated as complete garbage. this class is
    ##      only used by `unmangle_arguments` and thus both should be killed together.

    @classmethod
    def trimmed(cls, string, range, segments, whitespace=' '):
        '''Return a token for the given `string` with the characters in `whitespace` removed using both `range` and `segments`.'''
        left, right = range if isinstance(range, tuple) else (0, len(string))
        original = string[left : right]
        start, stop = (len(original) - len(F(*whitespace)) for F in [original.lstrip, original.rstrip])
        assert(all(string[left : right] in whitespace for left, right in segments[:start]))
        assert(all(string[left : right] in whitespace for left, right in segments[-stop:]) if stop else True)
        return (left + start, right - stop), segments[+start : -stop] if stop else segments[start:]

    @classmethod
    def parameters(cls, tree, string, range=None, assertion={'()', '<>'}, delimiter={','}):
        '''Use the given `tree` to yield a token for each item within the given `range` of `string` that is separated by `delimiter` and wrapped by `assertion`.'''
        start, stop = range if isinstance(range, tuple) else (0, len(string))
        assert(string[start:][:+1] + string[:stop][-1:] in assertion if assertion else True), string[start:][:+1] + string[:stop][-1:]
        adjustment, listable = 1 if assertion else 0, [(segment, items) for segment, items in token.split(string, range, tree[start], delimiter)]

        # start at the first list item and adjust the segment past the first
        # parenthese. if there's no items left, then adjust the ending too.
        segment, items = listable.pop(0)
        left, right = segment
        if listable:
            yield (left + adjustment, right), items or [(left + adjustment, right)]
        else:
            yield (left + adjustment, right - adjustment), items or [(left + adjustment, right - adjustment)]

        # continue consuming items until we have at least one element left.
        while len(listable) > 1:
            segment, items = listable.pop(0)
            yield segment, items
        assert(len(listable) <= 1), listable

        # the very last item should contain the closing parenthese..
        # hence, we need to adjust the segment we yield to cull it.
        while listable:
            segment, items = listable.pop(0)
            left, right = segment
            if right - adjustment > left:
                yield (left, right - adjustment), items or [(left, right - adjustment)]
            continue
        return

    @classmethod
    def prototype(cls, tree, string, range=None):
        '''Use the given `tree` with `range` on the prototype in `string` to return a tuple containing the result type, name, list of parameters, and list of qualifiers.'''
        start, stop = range if isinstance(range, tuple) else (0, len(string))
        branch, ignored, symbols = tree[start or None], {'', ' '}, {' ', '*', '&'}

        # start by finding the assumed parameters and using it as our pivot.
        iterable = (1 + index for index, (left, right) in enumerate(branch[::-1]) if string[left] + string[left : right][-1] == '()')
        parameters_index = next(iterable)

        # extract the qualifiers after the parameters, ignoring any
        # empty strings or spaces that don't have any other meaning.
        right, point = (start, stop) if not branch else branch[-parameters_index] if parameters_index else branch[-1]
        qualifiers = (point, stop), branch[-parameters_index:][1:] if point < stop else []

        # next token in the branch contains the parameters, we just need
        # to pop it off and skip all whitespace to get to the name.
        index, rindex, selection = 0, 1, branch[:-parameters_index] if parameters_index else branch[:]
        (stop, _), (left, right) = branch[-parameters_index], selection[-rindex] if selection else (start, stop)

        # here we're checking both (left, right) for the token and (right, stop).
        while rindex < len(selection) and string[right : stop] in ignored:
            if string[left : right] not in ignored:
                break
            index, rindex = rindex, rindex + 1
            stop, (left, right) = left, selection[-rindex]

        # if we got to the end, but "right" and "stop" are still the same, then
        # the prototype is not well-formed and there's still whitespace to trim.
        stop, name_index = (stop, index) if rindex < len(selection) or right != stop else (left, rindex)
        assert(all(string[left : right] for left, right in selection[-index:]))

        # first we need a list that filters away any tokens that are past
        # the "stop" index which references the end of the prototype name.
        iterable = selection[:] if not name_index else itertools.chain(selection[:-name_index], [selection[-name_index]]) if name_index < len(selection) else []
        filtered = [(left, right) for left, right in iterable if left < stop]

        # now that we have our list of relevant tokens, we just need to scan
        # backwards until the first symbol. then, everything inside is the name.
        iterable = (index for index, (left, right) in enumerate(filtered[::-1]) if string[left : right] in symbols)
        index = next(iterable, 0)

        # use the index to grab all tokens before the name. afterwards we
        # can figure out the point in front of it and then store its tokens.
        trimmed = filtered[:-index] if index else filtered[:]
        _, point = trimmed[-1] if trimmed else (None, start)
        name = (point, stop), filtered[-index:] if index else []

        # everything else that we've trimmed contains the calling convention,
        # the result type, and the scope. we only need to skip the whitespace.
        index, rindex, stop = 0, 1, point
        while rindex <= len(trimmed) and string[slice(*trimmed[-rindex])] in ignored:
            left, right = trimmed[-rindex]
            if stop != right:
                break
            stop, index, rindex = left, rindex, rindex + 1

        # reset "stop" if it was malformed, and verify that we only trimmed whitespace.
        stop, _ = trimmed[-index] if index else trimmed[-1] if trimmed else (start, point)
        assert(all(string[left : right] in ignored for left, right in trimmed[-index:]))

        # that should be it.. we have every component and can return them.
        result_and_convention = (start, stop), trimmed[:-index] if index else trimmed[:]
        parameters_range = branch[-parameters_index]
        return result_and_convention, name, parameters_range, qualifiers

    @classmethod
    def declaration_and_name(cls, string, range, segments):
        '''Use the given `range` on the trimmed `string` with `segments` to return a selection of its declaration and segment for its name.'''
        start, stop = range if isinstance(range, tuple) else (0, len(string))
        ignored, symbols = {'', ' '}, {' ', '*', '&'}

        # scan for the name until we get to a symbol to pivot from.
        iterable = (1 + index for index, (left, right) in enumerate(segments[::-1]) if string[left : right] in symbols)
        pivot = next(iterable, 0)
        (_, point) = segments[-pivot] if pivot else (stop, stop)
        name_segment = (point, stop)

        # now we can scan left from the pivot to identify any whitespace.
        iterable = segments[:] if not pivot else itertools.chain(segments[:-pivot], [segments[-pivot]]) if pivot < len(segments) else []
        selection = [(left, right) for left, right in iterable]

        index, rindex, stop = 0, 1, point
        while rindex <= len(selection) and string[slice(*selection[-rindex])] in ignored:
            left, right = selection[-rindex]
            if stop != right:
                break
            stop, index, rindex = left, rindex, rindex + 1

        # we have the name and the slice for the type which we can return.
        declaration = (start, stop), selection[:-index] if index else selection[:]
        return declaration, name_segment

    @classmethod
    def name_and_template(cls, string, range, segments, delimiter={'::'}, template='<>'):
        '''Use the given `range` on the trimmed `string` with `segments` to yield each component of a name delimited by `delimiter` as a tuple composed of the range for the name and its template parameters.'''
        start, stop = range if isinstance(range, tuple) else (0, len(string))
        ignored, delimiters = {'', ' '}, {' ', '*', '&'}

        # first we need to figure out where the name begins
        # by scanning for the very first delimiter (space).
        iterable = (1 + index for index, (left, right) in enumerate(segments[::-1]) if string[left : right] in delimiters)
        index = next(iterable, 0)
        selected = segments[-index:] if index else segments[:]
        _, start = selected.pop(0) if index else (start, start)

        # now we have the range and segments for the entire name. we just need
        # to check if it's a template, and extract its parameters if it is.
        for (left, right), segments in token.split(string, (start, stop), selected, delimiter):
            tail = start, stop = segments.pop() if segments else (right, right)
            item = string[start : stop]
            tail = point, _ = tail if item[:1] + item[-1:] == template else (right, right)
            yield (left, point), tail
        return

    @classmethod
    def function_pointer(cls, string, range, segments):
        '''Use the given `range` on the trimmed `string` with `segments` to return a tuple containing the result type, and the segments of both the calling convention and parameters.'''
        start, stop = range if isinstance(range, tuple) else (0, len(string))
        ignored, symbols = {'', ' '}, {' ', '*', '&'}

        # first we need to find the parameters.
        iterable = (1 + index for index, (left, right) in enumerate(segments[::-1]) if string[left] + string[left : right][-1] == '()')
        parameters_index = next(iterable)
        assert(all(string[left : right] in ignored for left, right in segments[-parameters_index:][1:]))

        # then we continue to find the convention, pointer, and name.
        pointer_index = next(iterable)
        assert(all(string[left : right] in ignored for left, right in segments[-pointer_index : -parameters_index:][1:]))

        # next we need to skip any whitespace to find the range of the result.
        result_segments, (stop, _) = segments[:-pointer_index], segments[-pointer_index]
        index, rindex = 0, 1
        while rindex <= len(result_segments) and string[slice(*result_segments[-rindex])] in ignored:
            left, right = result_segments[-rindex]
            if stop != right:
                break
            stop, index, rindex = left, rindex, rindex + 1

        # that was it, just need to pack the result and return each part.
        result = (start, stop), result_segments[:-index] if index else result_segments[:]
        return result, segments[-pointer_index], segments[-parameters_index]

    @classmethod
    def function_pointer_convention(cls, string, range, segments, assertion={'()'}, symbols={'*', '&'}, whitespace={' '}):
        '''Use the given `range` on both `string` and `segments` to return a tuple containing the calling convention, the segments of each symbol, and the tokens that compose the name.'''
        start, stop = range if isinstance(range, tuple) else (0, len(string))
        assert(string[start:][:+1] + string[:stop][-1:] in assertion if assertion else True), string[start:][:+1] + string[:stop][-1:]
        adjustment, ignored = 1 if assertion else 0, {item for item in symbols} | whitespace

        # now we can shrink our range excluding the parentheses, and then extract
        # the convention from the start up to the very first symbol of some sort.
        start, stop = start + adjustment, stop - adjustment
        left, right = segments[0] if segments else (start, start)
        convention, start = (start, left), left

        # next, we keep consuming tokens while they're contiguous and they're
        # symbols. this should give us the reference depth of the pointer.
        index, point = 0, left
        while index < len(segments) and string[left : right] in ignored:
            left, right = segments[index]
            if point != left:
                break
            point, index = right, index + 1

        # now we have the starting point that the name begins
        # at along with all of the segments that compose it.
        name = (point, stop), segments[index:]

        # everything we skipped is the pointer definition where each
        # segment is contiguous and we only need it filtered to return.
        pointers = [(left, right) for left, right in segments[:index] if string[left : right] not in whitespace]
        return convention, pointers, name

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
                segment = left, right = stack.pop(), index + length
                layer = tree.setdefault(stack[-1] if stack else None, [])
                order.append(segment), layer.append(segment), tree.setdefault(left, [])
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

    @classmethod
    def augment(cls, index, segments):
        '''Return the given `segments` starting at `index` into a list of sizes that can be used for iterating through the tokens in a string.'''
        (start, _) = index if isinstance(index, tuple) else (index, index)
        skip, result = start or 0, []
        for left, right in segments:
            key, skip, size = left, left - skip, right - left   # what makes this list special is that we're preserving
            result.append((skip, key, size))                    # "left" since it's used as an index into the tree.
            skip = right
        return result

    @classmethod
    def unaugment(cls, index, augment):
        '''Return the list of sizes given by `augment` as a range and list of segments that start at `index`.'''
        (start, _) = index if isinstance(index, tuple) else (index, index)
        position, result = start or 0, []
        for skip, index, size in augment:
            position += skip
            assert(position == index), (position, index)
            result.append((position, position + size))
            position += size
        return (start or 0, position), result

    @classmethod
    def reversed(cls, string, range, segments):
        '''Return the specified `range` and `segments` translated for the reversed version of the given `string`.'''
        (start, stop) = range if isinstance(range, tuple) else (0, len(string) if hasattr(string, '__len__') else string)
        result, point = [], len(string)
        for left, right in segments:
            result.append((point - right, point - left))
        return (point - stop, point - start), result[::-1]

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
            _, position = result.extend([skipped, original if modified is None else modified]), position + size
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
        augmented = {index : cls.augment(segments) for index, segments in tree.items()}

        #assert(verify(tree, ordered) and len(ordered) == 0)
        #assert(sum(string.count(token) for token in tokens) == sum(map(len, tokens)) * sum(map(len, tree.values())) + len(errors))

        # Our closure uses lists, so we need to gather our results into one
        # so that we can join it into a string at the end and yield it.
        result = []
        coro = closure(result.append, string, augmented)
        try:
            component = next(coro)
            while True:
                suggestion = (yield component)
                component = coro.send(component if suggestion is None else suggestion)
        except StopIteration:
            pass

        # Now we should have our transformed result and just need to
        # join it back into a string before we yield it to the caller.
        yield ''.join(result)

    @classmethod
    def segments(cls, range, segments=None):
        '''Yield each segment within the given `range` using the points defined by `segments`.'''
        start, stop = range
        assert(start <= stop), (start, stop)
        for item in segments or []:
            point, _ = item
            point = max(point, start)
            if start < point:
                yield start, min(point, stop)
            _, start = item
            start = min(start, stop)
            yield point, start
        if start < stop:
            yield start, stop
        return

    @classmethod
    def split(cls, string, range, segments, tokens={}):
        '''Use the `range` and `segments` associated with `string` to yield each selection that is delimited by any of the given `tokens`.'''
        start, stop = range if isinstance(range, tuple) else (0, len(string))
        assert(start <= stop), (start, stop)
        result = []
        for item in segments:
            left, right = item
            # ignore any tokens that do not start in range.
            if not (start <= left < stop):
                continue
            # if we matched, yield our state and reset.
            elif string[left : right] in tokens:
                yield (start, left), result
                result, start = [], right
            # only collect tokens that stop within range.
            elif start < right <= stop:
                result.append((left, right))
            continue
        yield (start, stop), result

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
        groups = {length: [{token for token in group} for group in zip(*pairs)] for length, pairs in itertools.groupby(sorted(tokens, key=len), len)}
        layer, [capture], (open, close) = (groups.pop(length, length * [()]) for length in range(3))
        assert(not groups), groups

        # We first need a stack that will store the index of the beginning of
        # each pair. We also store two tables for tracking mismatches. One tracks
        # stacks specific to a pair, the other maps a close token to an open one.
        stack, pairs = [], {pair[-1] : pair[0] for pair in tokens if len(pair) == 2}
        locations = {token : list for token, list in itertools.chain(*((lambda pair, listref: [(pair[0], listref), (pair[-1], listref)])(pair, []) for pair in filter(None, tokens)))}

        # Now we can enter the main loop that packs each grouped pair into a
        # tree. We maintain two stacks so we can check them against each other.
        owner, tree, order, errors = [None], {None : layer}, [], []
        for index, length in cls.indices(string, locations):
            token = string[index : index + length]
            if token in open:
                stack.append(index), locations[token].append(index), owner.append(index)
            elif token in close and locations[token] and locations[token][-1] == stack[-1] and string[stack[-1]] == pairs[token]:
                segment = stack.pop(), index + length
                layer = tree.setdefault(stack[-1] if stack else None, [])
                order.append(segment), layer.append(segment), tree.setdefault(locations[token].pop(), []), owner.pop()
            elif token in capture:
                segment = index, index + length
                tree.setdefault(owner[-1], []).append(segment)
            else:
                errors.append((index, index + length))
            continue

        # If the stack isn't empty, then we encountered some mismatched pairs
        # (errors) in the beginning of the string and we need to return them first.
        if stack:
            return order, tree, sorted(itertools.chain(*([(index, index + len(token)) for index in locations[token]] for token in open))) + errors
        return order, tree, errors

class unmangled(object):
    """
    This namespace provides tools that interact with an unmangled name and
    specifically for transforming a declaration in its unmangled form. This
    is primarily used for stripping invalid characters from different name
    components which might not be parsable by the disassembler.
    """

    # XXX: this declarations are definitely not accurate and need some
    #      research done (by someone else) to their correct names.
    _declaration_rules = {
        "`anonymous namespace'":                            'anonymous',
        "`base-instance'":                                  'base_instance',
        "`class constructor`":                              'constructor',
        "`class destructor`":                               'destructor',
        "`construction vtable for'":                        'construction_vtable_',
        "`copy constructor closure'":                       'copy_constructor_closure',
        "`copy-region-'":                                   'copy_region_',
        "`covariant return thunk to'":                      'covariant_return_',
        "`default constructor closure'":                    'constructor_closure',
        "`dynamic atexit destructor for '":                 'dynamic_atexit_',
        "`dynamic initializer for '":                       'initializer_',
        "`eh vector constructor iterator'":                 'eh::__vec_ctor',
        "`eh vector copy constructor iterator'":            'eh::__vec_copy',
        "`eh vector destructor iterator'":                  'eh::__vec_dtor',
        "`eh vector vbase constructor iterator'":           'eh::__vec_ctor_vb',
        "`eh vector vbase copy constructor iterator'":      'eh::__vec_copy_vb',
        "`global constructor keyed to'":                    'constructor_',
        "`global destructor keyed to'":                     'destructor_',
        "`guard variable for'":                             'guard_variable_',
        "`local static destructor helper'":                 'static_destructor_helper',
        "`local static guard'":                             'static_guard',
        "`local static thread guard'":                      'static_thread_guard',
        "`local vftable constructor closure'":              'vftable_constructor_closure',
        "`local vftable'":                                  'vftable',
        "`managed vector constructor iterator'":            'managed::__vec_ctor',
        "`managed vector copy constructor iterator'":       'managed::__vec_copy',
        "`managed vector destructor iterator'":             'managed::__vec_dtor',
        "`non-virtual thunk to'":                           'static_thunk_',
        "`omni callsig'":                                   'omni_callsig',
        "`placement delete[] closure'":                     'placement_delete_array_closure',
        "`placement delete closure'":                       'placement_delete_closure',
        "`scalar deleting destructor'":                     'scalar_deleting_destructor',
        "`static-initialization-fun'":                      'static_initialization',
        "`static-termination-fun'":                         'static_termination',
        "`string literal'":                                 'string',
        "`string'":                                         'string',
        "`template-parameter'":                             'template_parameter',
        "`template static data member constructor helper'": 'static_template_helper_constructor',
        "`template static data member destructor helper'":  'static_template_helper_destructor',
        "`temp-'":                                          'temp_',
        "`typeinfo for'":                                   'typeinfo_',
        "`typeinfo name for'":                              'typename_',
        "`typeof'":                                         'typeof',
        "`udt returning'":                                  'udt_returning',
        "`vbase destructor'":                               'vbase_destructor',
        "`vbtable'":                                        'vbtable',
        "`vcall'":                                          'vcall',
        "`vector constructor iterator'":                    '__vec_ctor',
        "`vector copy constructor iterator'":               '__vec_copy',
        "`vector deleting destructor'":                     '__vec_dtor',
        "`vector destructor iterator'":                     '__vec_dtor',
        "`vector vbase constructor iterator'":              '__vec_ctor_vb',
        "`vector vbase copy constructor iterator'":         '__vec_copy_vb',
        "`vftable'":                                        'vftable',
        "`virtual-base-instance'":                          'vbaseinstance',
        "`virtual-base-ptr'":                               'vbaseptr',
        "`virtual displacement map'":                       'vdispmap',
        "`virtual-fn-table-ptr-table'":                     'vfunctable_ptrt',
        "`virtual-fn-table-ptr'":                           'vfunctable_ptr',
        "`virtual thunk to'":                               'thunk_',
        "`vtable for'":                                     'vtable_',
        "`vtbl'":                                           'vtable',
        "`VTT for'":                                        'vtt_',

        # runtime-type information
        #"`RTTI ":                               'rtti_',
        "`RTTI Base Class Descriptor at ":      'rtti_base_descriptor_',
        "`RTTI Base Class Array'":              'rtti_base_array_',
        "`RTTI Class Hierarchy Descriptor'":    'rtti_descriptor',
        "`RTTI Complete Object Locator'":       'rtti_locator',

        # unknown
        "`__vdthk__'": '__vdthk__',

        # XXX: pragmas i guess?
        #"`adjustor{": '',
        #"`vtordisp{": '',
    }

    # pre-calculate the prefixes and suffixes that we'll use to trim and match each component
    _declaration_prefix_suffix = {item[:1] : item[-1:] for item in _declaration_rules}

    # random keywords that aren't worth anything other than unnecessary whitespace (really).
    _declaration_keywords = {'enum ', 'struct ', 'union ', 'class ', 'const ', 'volatile '}

    # operators
    _declaration_operators = {
        'operator new':         'new',
        'operator delete':      'delete',
        'operator new[]':       'new_array',
        'operator delete[]':    'delete_array',

        'operator=':            'assign',
        'operator[]':           'subscript',
        'operator->':           'pointer',
        'operator->*':          'pointer_member',
        'operator,':            'comma',
        'operator()':           'call',

        'operator++':           'increment',
        'operator--':           'decrement',
        'operator+':            'add',
        'operator-':            'subtract',
        'operator*':            'multiply',
        'operator/':            'divide',
        'operator%':            'remainder',
        'operator<<':           'shiftleft',
        'operator>>':           'shiftright',

        'operator!':            'not',
        'operator==':           'equal',
        'operator!=':           'notequal',
        'operator<':            'less',
        'operator<=':           'lessequal',
        'operator>':            'greater',
        'operator>=':           'greaterequal',
        'operator<=>':          'spaceship',

        'operator&&':           'and',
        'operator||':           'or',

        'operator~':            'bnot',
        'operator&':            'band',
        'operator|':            'bor',
        'operator^':            'bxor',

        'operator+=':           'add_assign',
        'operator-=':           'subtract_assign',
        'operator*=':           'multiply_assign',
        'operator/=':           'divide_assign',
        'operator%=':           'remainer_assign',
        'operator<<=':          'shiftleft_assign',
        'operator>>=':          'shiftright_assign',

        'operator&=':           'band_assign',
        'operator|=':           'bor_assign',
        'operator^=':           'bxor_assign',
    }

    # scopes
    _declaration_scopes = { 'private: ', 'protected: ', 'public: ' , '[thunk]: '}

    @classmethod
    def keyword(cls, string):
        '''Return the given `string` with any known keywords or qualifiers removed.'''
        iterable = (keyword for keyword in cls._declaration_keywords if keyword in string)
        return functools.reduce(lambda string, keyword: string.replace(keyword, ''), iterable, string).strip()

    @classmethod
    def name(cls, string):
        '''Return a parsable variation of `string` if it is a known function or type.'''
        if string[:1] not in cls._declaration_prefix_suffix:
            return string

        # we slice up the string like this so that we can do lookups in O(1).
        suffix = cls._declaration_prefix_suffix[string[:1]]
        stop = 1 + string[1:].find(suffix)
        key = string[:stop + 1]
        return cls._declaration_rules.get(key, key) + string[stop + 1:] if stop > 0 else string

    @classmethod
    def operator(cls, string):
        '''Return a parsable variation of `string` if it is a known operator`.'''
        return cls._declaration_operators.get(string, string)

    @classmethod
    def scope(cls, string):
        '''Return the given `string` without its scope if one was found at its beginning.'''
        index = string.find(': ')
        start = index + 2
        return string if index < 0 else string[start:] if string[:start] in cls._declaration_scopes else string

    @classmethod
    def variable(cls, string):
        '''Return the name and type specifier of the variable declaration in `string`.'''
        Fvalidate = idaapi.validate_name2 if idaapi.__version__ < 7.0 else utils.frpartial(idaapi.validate_name, idaapi.SN_IDBENC)

        # Use validate_name (in a very inefficient way) until we encounter an index to stop at.
        name, reversed = utils.string.to('_'), utils.string.to(string[::-1])
        for index, _ in enumerate(reversed):
            name += reversed[index : index + 1]
            if Fvalidate(name) != name:
                break
            continue

        # If we completed processing the entire string, then the string is not a declaration
        # with a name and type. So, we just assume that was the name..and return it typeless.
        else:
            return string, ''

        # Now we can slice our variable name out, and use its length to slice out the type.
        variable_name = string[-len(reversed[:index]):] if index > 1 else ''
        return variable_name, string[:-len(variable_name)] if len(variable_name) else string

    @classmethod
    def parameters(cls, string):
        '''Parse a comma-separated `string` containing function parameters or template specifiers and return them as a list.'''
        _, tree, _ = token.parse(string, ['()', '<>', ','])
        indices = [start for start, stop in tree.get(None, []) if stop - start == 1][::-1]

        # Gather all of the ranges for each parameter inside the "," characters.
        result, left, right = [], 1 if string[:1] in '()<>' else 0, len(string)
        for index in indices[::-1]:
            _, left = result.append((left, index)), index + 1
        result.append((left, len(string)))

        # Use the results to return a list of strings containing each parameter.
        return [string[left : right] for left, right in result]

    __parsable_valid = {character for character in itertools.chain(_string.ascii_letters, _string.digits, u'_$:')}
    @classmethod
    def parsable(cls, string):
        '''Transform the given `string` to the required characters for it to be parseable without complaints.'''
        string = cls.scope(string)

        # first check if there's any unmangled characters within our symbol. if there aren't any, then
        # we explicitly check for any constructors/destructors and replace it if it matches the typename.
        if not any(string.count(character) for character in "<>`'() "):
            destructor = string.split('::~')
            string = '::'.join([destructor[0], 'destructor']) if len(destructor) == 2 and destructor[0].endswith(destructor[1]) else string
            constructor = string.split('::')
            components = constructor[:-1] + ['constructor'] if len(constructor) > 1 and constructor[-2].endswith(constructor[-1]) else constructor

            # check individual components for valid symbols before joining them back together.
            iterable = (''.join(ch if ch in cls.__parsable_valid else '_' for ch in item) for item in components)
            return internal.utils.string.of('::'.join(iterable))

        # remove all stupid keywords and then parse our string to figure out where a templates might be at.
        string = cls.keyword(string)
        order, tree, _ = nested.parse(string, ['<>'])
        _, stop = order[-1] if order else (0, len(string.strip()[:-1]))

        # if there's a closing-parenthesis within the last slice, then we need to strip out some parameters.
        # FIXME: it is because of this that function names might not be unique. it'll probably be better to
        #        encode these parameters with single-character codes rather than stripping them.
        if ')' in string[stop:]:
            open, close = nested.last(string, '()')
            string = string[:open] + string[close:] if open < close else string

        # now we can use strip_templates to strip out any and all templates depth-first.
        stripper = cls.__strip_templates(string)
        string = nested.process(stripper.send, next(stripper), {index : nested.augment(segments) for index, segments in tree.items()})

        # if there's any other parentheses in the string, then they're unbalanced and need filtering.
        anti_parenthesis = {character : '_' for character in '()'}
        if any(character in string for character in anti_parenthesis):
            string = ''.join(itertools.starmap(anti_parenthesis.get, zip(string, string)))

        # then we fix up each individual component and extract the type to remove it.
        string = '::'.join(cls.operator(cls.name(item)) for item in string.split('::'))
        string, type = cls.variable(string.replace(',', '_')) if ' ' in string else (string, '')

        # that should be it and all we need to do is replace all spaces with underscores.
        assert(not any(string.count(character) for character in "<>`'()")), string
        return cls.parsable('_'.join(string.split(' ')))

    @classmethod
    def __strip_function_type(cls, string):
        '''Internal function that strips all unparsable characters from a function pointer type definition.'''
        if any(character in string for character in '()'):
            left, right = nested.last(string, '()')
            type_and_pointer, parameters, qualifier = string[:left], string[left : right], string[right:]
            assert(parameters), parameters

            # go through all of the parameters separated by a ',' to strip out qualifiers and types.
            parameters = [item.replace(' ', '').replace(' *', '_ptr') for item in unmangled.parameters(parameters[+1 : -1])]

            # split up the type and pointer by deleting the pointer and removing spaces.
            left, right = nested.last(type_and_pointer, '()')
            type = type_and_pointer[:left] if left <= right else type_and_pointer
            type = type.replace(' ', '').replace('*', '_ptr')

            # FIXME: rather than replacing parameters like we are, it would be a significant
            #        improvement to encode them somehow so that we can preserve their value.

            # join all this crap back together again and cull out all the spaces.
            return '$'.join(["funcptr{:d}${:s}".format(1 + len(parameters), type)] + parameters)
        return string

    @classmethod
    def __strip_templates(cls, string):
        '''Internal coroutine that will strip out the different parts of a template definition.'''
        string = string
        while True:
            string = (yield string)
            if not string:
                continue

            # if we received an empty string, then there's nothing to do.
            if not string:
                continue

            # first we'll trim out the '<>' from the entire component
            assert(string[0], string[-1]) == ('<', '>'), string
            trimmed = string[+1 : -1]

            # go through all parts separated by a "," to strip out any qualifiers,
            # replace all pointers, method-names, and operators with parsable variations.
            iterable = (item.strip() for item in cls.parameters(trimmed))
            iterable = (item.replace(' *', '_ptr') for item in iterable)
            iterable = (cls.__strip_function_type(item) for item in iterable)
            iterable = (cls.operator(cls.name(item)) for item in iterable)

            # FIXME: rather than stripping parameters...a better idea would be to encode
            #        them so that way we can preserve their uniqueness.

            # now we join everything back together, replacing the "<>" with "$$".
            string = '$$' + '$'.join(iterable) + '$$'
        return

class convention(object):
    """
    This namespace exists for converting the user's specification
    of a calling convention to the codes that the disassembler
    uses. This way the special calling conventions used by the
    disassembler can be interpreted by us, or specified by the
    user in shorthand.
    """

    # 1-1 mapping of the user's choice to the convention code.
    available = {
        '__cdecl': idaapi.CM_CC_CDECL,
        '__stdcall': idaapi.CM_CC_STDCALL,
        '__thiscall': idaapi.CM_CC_THISCALL,
        '__fastcall': idaapi.CM_CC_FASTCALL,
        '__pascal': idaapi.CM_CC_PASCAL,

        # the following conventions are special, and aren't really well supported by us.
        #'__usercall': idaapi.CM_CC_SPECIAL,     # preserves stack
        #'__usercall': idaapi.CM_CC_SPECIALP,    # purges stack
        #'__usercall': idaapi.CM_CC_SPECIALE,    # includes ellipsis
    }

    # list that the user is allowed to choose from and match with.
    choice = {
        '__cdecl': {idaapi.CM_CC_CDECL, idaapi.CM_CC_VOIDARG, idaapi.CM_CC_ELLIPSIS},
        '__stdcall': {idaapi.CM_CC_STDCALL, idaapi.CM_CC_VOIDARG},
        '__thiscall': {idaapi.CM_CC_THISCALL},
        '__fastcall': {idaapi.CM_CC_FASTCALL},
        '__pascal': {idaapi.CM_CC_PASCAL},

        # XXX: __usercall is special and we interpret it as either >= CM_CC_MANUAL, but excluding CM_CC_GOLANG if it exists
        '__usercall': {cc & idaapi.CM_CC_MASK for cc in range(getattr(idaapi, 'CM_CC_MANUAL', 0x90), 0x100)},
    }

    # aliases that can resolve to one of our choices.
    aliases = {
        '__cdecl': ['cdecl'],
        '__stdcall': ['std', 'stdcall'],
        '__pascal': ['pascal'],
        '__fastcall': ['fast', 'fastcall'],
        '__thiscall': ['this', 'thiscall'],
        idaapi.CM_CC_VOIDARG: ['void', 'voidarg'],
        '__usercall': ['user'],

    # these are all integers that the user can alias if they want.
        idaapi.CM_CC_ELLIPSIS: ['...', 'dotdotdot', Ellipsis],
        idaapi.CM_CC_UNKNOWN: ['?', None],
    }

    # if CM_CC_GOLANG is defined, then add it and remove it from
    # our __usercall set. we also need to add its alias too.
    if hasattr(idaapi, 'CM_CC_GOLANG'):
        available['__golang'] = idaapi.CM_CC_GOLANG
        choice['__golang'] = {idaapi.CM_CC_GOLANG}
        choice['__usercall'] -= {idaapi.CM_CC_GOLANG}
        aliases['__golang'] = ['go', 'golang']

    # now we'll just do some functional tricks to update our
    # list of choices and mappings with each of their aliases.
    # XXX: we need a lambda to capture our dicts because python devers are
    # retarded and they couldn't figure out how to avoid leaking locals.
    # this is discussed in python/cpython#47942, but i'm not holding my breath.
    (lambda choice, iterable: [functools.reduce(utils.freverse(choice.setdefault), aliases, choice.get(key, {key})) for key, aliases in iterable])(choice, aliases.items())
    (lambda available, iterable: [functools.reduce(utils.freverse(available.setdefault), aliases, available.get(key, key)) for key, aliases in iterable])(available, aliases.items())

    @classmethod
    def matches(cls, *conventions):
        '''Return a closure that when compared against an `idaapi.CM_CC_*` code will return true if matching one of the user's `conventions`.'''
        iterable = (cls.choice.get(convention, {convention}) for convention in conventions)
        result = functools.reduce(operator.or_, iterable, {empty for empty in []})
        return functools.partial(operator.contains, result)

    @classmethod
    def get(cls, convention):
        '''Return the `idaapi.CM_CC_*` code for the given `convention` provided as an integer or a string.'''
        result = cls.available.get(convention, convention)
        if isinstance(result, types.integer) and result & idaapi.CM_CC_MASK == result:
            return result
        cclookup = {item for item in cls.available if isinstance(item, types.string) and item.startswith('__')}
        raise internal.exceptions.InvalidParameterError(u"{:s}.get({!r}) : The convention that was specified ({:s}) is not one of the known types ({:s}).".format('.'.join([__name__, cls.__name__]), convention, "{:d}".format(convention) if isinstance(convention, types.integer) else "{!r}".format(convention), ', '.join(cclookup)))
