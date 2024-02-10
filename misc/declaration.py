"""
Declaration module (internal)

This module contains some tools used for extracting information out of
function and type declarations.

TODO: Implement parsers for some of the C++ symbol manglers in order to
      query them for specific attributes or type information.
"""
import functools, operator, itertools, logging, string as _string

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
        if all(len(original) > item for item in [start, stop]):
            return (left + start, right - stop), segments[+start : -stop] if stop else segments[start:]
        bounds = (left, right - stop) if len(original) <= stop else (left + start, right)
        return bounds, segments[+start : -stop] if stop else segments[start:]

    @classmethod
    def parameters(cls, tree, string, range=None, assertion={'()', '<>', '{}'}, delimiter={','}):
        '''Use the given `tree` to yield a token for each item within the given `range` of `string` that is separated by `delimiter` and wrapped by `assertion`.'''
        start, stop = range if isinstance(range, tuple) else (0, len(string))
        assert(string[start:][:+1] + string[:stop][-1:] in assertion if assertion else True), string[start:][:+1] + string[:stop][-1:]
        adjustment, listable = 1 if assertion else 0, [(segment, items) for segment, items in token.split(string, range, tree[start], delimiter)]

        # start at the first list item and adjust the segment past the first
        # parenthese. if there's no items left, then adjust the ending too.
        segment, items = listable.pop(0)
        left, right = segment
        if listable:
            yield (left + adjustment, right), items
        else:
            yield (left + adjustment, right - adjustment), items

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
                yield (left, right - adjustment), items
            continue
        return

    @classmethod
    def prototype(cls, tree, string, range=None):
        '''Use the given `tree` with `range` on the prototype in `string` to return a tuple containing the result type with convention, name, segment for parameters, and list of segments for qualifiers.'''
        start, stop = range if isinstance(range, tuple) else (0, len(string))
        ignored, symbols = {'', ' '}, {' ', '*', '&'}

        # start by extracting away the qualifiers that we need to return and
        # in exchange we'll have the declaration that we need to interpret.
        declaration, qualifiers = cls.declaration(string, range, tree[start or None])
        (start, stop), segments = declaration

        # now the last segment of our declaration should be our parameters.
        parameters_range = stop, _ = left, right = segments.pop() if segments else (len(string), len(string))
        assert(string[left : left + 1] + string[right - 1 : right] == '()'), string[left : right]

        # XXX: we're using a hack to deal with "`adjustor(x)' ", due to not being in
        # a demangled name. we can just pop the last segment (with the " ") to deal.
        segments.pop() if string[stop - 2 : stop] == "' " else None

        # since we should be being used to parse output from the disassembler,
        # we can assume that everything up to the first whitespace is the name.
        beginning, name = cls.ending(string, (start, stop), segments, delimiters=' ')
        (start, stop), segments = beginning

        # loop in order to consume any of the trailing whitespace that's in the
        # ignored set, that should trim the convention and we should be done.
        point = stop
        while segments:
            left, right = segments[-1]
            if string[right : point] not in ignored:
                break

            # consume all whitespace within a segment.
            _, point = segments[-1]
            if string[left : right] not in ignored:
                break

            # remove the last segment, and set the pointer to its beginning.
            point, _ = segments.pop()

        # that should be it.. we have every component and can return them.
        result_and_convention = (start, point), segments
        return result_and_convention, name, parameters_range, qualifiers

    @classmethod
    def declaration(cls, string, range, segments, qualifiers={'const', 'volatile', 'throw()', 'throw(void)', 'noexcept', '[clone]'}):
        '''Use the given `range` and `segments` with `string` to return a tuple containing the selection for the type and a list of segments for its qualifiers.'''
        start, stop = range if isinstance(range, tuple) else (0, len(string))
        ignored = {item for item in itertools.chain([''], (qualifier[qualifier.rindex('('):] for qualifier in qualifiers if qualifier[-1] in ')'))}
        symbols, requested = {'*', '&'}, {'*', '&'} | qualifiers

        # most of the work is handled when stripping out the qualifiers.
        decl, quals = cls.qualifiers(string, (start, stop), segments, qualifiers=qualifiers)

        # we just need to clean up the qualifiers and convert them
        # from a selection into the segments that we care about.
        (start, stop), segments = quals
        iterable = ((string[left : right], (left, right)) for left, right in segments)
        iterable = (segment for item, segment in iterable if item[:1] + item[-1:] not in ignored)
        result = [(left, right) for left, right in token.segments((start, stop), iterable) if string[left : right] in requested]

        # now we can return the declaration along with the segments for the qualifiers.
        return decl, result

    @classmethod
    def qualifiers(cls, string, range, segments, qualifiers={'const', 'volatile', 'throw()', 'throw(void)', 'noexcept'}):
        '''Return a tuple containing the selections for the declaration and qualifiers using the given `range` and `segments` with `string`.'''
        start, stop = range if isinstance(range, tuple) else (0, len(string))
        symbols, cuddled = {'', ' ', '*', '&'}, {item for item in itertools.chain((qualifier[qualifier.rindex('('):] for qualifier in qualifiers if qualifier[-1] in ')'))}

        # special case: if the whole string is a qualifier, then return it.
        if string[start : stop] in qualifiers:
            declaration = (start, start), []
            qualifiers = (start, stop), segments
            return declaration, qualifiers

        # loop while each element is contiguous and a symbol or a candidate.
        rindex, leftover = 0, segments[:]
        point = left = stop
        while left > start:
            left, right = leftover.pop() if leftover else (start, start)

            # if it's a valid qualifier, then adjust our point to the next contiguous
            # one so that the following contiguity(?) check will actually pass.
            if string[right : point] in qualifiers:
                point = right

            # if the segment is non-contiguous, then it's either a qualifier or
            # it's not. in this case, due to the previous check, it's not one.
            if point != right:
                break

            # if it's a symbol, then shift to the next contigous position.
            elif string[left : right] in symbols:
                point, pivot = left, right

            # if it's a candidate qualifier, then peek at the next segment and try
            # to confirm it. if we didn't confirm, then we can abort processing.
            elif string[left : right] in cuddled:
                pivot, left = leftover[-1] if leftover else (start, start)
                if string[left : right] not in qualifiers:
                    point = right
                    break
                point = right = left

            # if it was nothing we know about, then we can also just abort.
            else:
                point = right
                break
            rindex += 1

        # now we can use the determined point as a pivot, and slice up the segments.
        declaration = (start, point), segments[:-rindex] if rindex else segments
        qualifiers = (point, stop), segments[-rindex:] if rindex else []
        return declaration, qualifiers

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
    def keyword(cls, string, range, segments, delimiters={' '}, keywords={'class', 'struct', 'union', 'enum'}):
        '''Use the given `string` with `range` and `segments` to return a tuple with the requested `keywords` prior to `delimiters` and the resulting selection.'''
        start, stop = range if isinstance(range, tuple) else (0, len(string))

        # scan for the very first delimiter and grab its index.
        iterable = (index for index, (left, right) in enumerate(segments) if string[left : right] in delimiters)
        index = next(iterable, len(segments))

        # use the index of the delimiter to check if we start with a valid
        # keyword. if we found one, then we need to strip it from the selection.
        point, _ = segments[index] if index < len(segments) else (start, start)
        candidate = string[start : point]
        if candidate in keywords:
            _, point = segments[index] if index < len(segments) else (stop, stop)
            result = (point, stop), segments[index + 1:]
            return candidate, result

        # otherwise we just return exactly what we were given.
        selection = (start, stop), segments
        return '', selection

    @classmethod
    def beginning(cls, string, range, segments, delimiters={' ', '*', '&'}):
        '''Use the given `string` with `range` and `segments` to return a tuple containing the selections before and after the first instance of any `delimiters`.'''
        start, stop = range if isinstance(range, tuple) else (0, len(string))

        # scan forwards until we encounter one of the given delimiters.
        iterable = (index for index, (left, right) in enumerate(segments) if string[left : right] in delimiters)
        index = next(iterable, len(segments))

        # select our result and pivot around the discovered point (exclusive).
        selected = segments[:index] if index < len(segments) else segments[:]
        point, _ = segments[index] if index < len(segments) else (stop, stop)
        result = (start, point), selected

        # everything we didn't process contains the ending, so slice
        # it up so that we can also return it with the selection.
        ending = (point, stop), segments[len(selected):]
        return result, ending

    @classmethod
    def ending(cls, string, range, segments, delimiters={' ', '*', '&'}):
        '''Use the given `string` with `range` and `segments` to return a tuple containing the selections before and after the last instance of any `delimiters`.'''
        start, stop = range if isinstance(range, tuple) else (0, len(string))

        # scan backwards until we encounter one of the chosen delimiters.
        iterable = (1 + index for index, (left, right) in enumerate(segments[::-1]) if string[left : right] in delimiters)
        index = next(iterable, 0)

        # now we can select our result and pivot around the discovered point.
        selected = segments[-index:] if index else segments[:]
        _, point = selected.pop(0) if index else (start, start)
        result = (point, stop), selected

        # everything in front of the point is the beginning, so
        # we can just return that along with our selection.
        beginning = (start, point), segments[:-len(selected)] if selected else segments[:]
        return beginning, result

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

        # then we continue to find the convention, pointer, and name. if we couldn't
        # find another pair of parentheses, then this is a functor and has no convention.
        pointer_index = next(iterable, parameters_index)
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
        return result, (stop, stop) if pointer_index == parameters_index else segments[-pointer_index], segments[-parameters_index]

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
                depth, layer = len(stack), tree.setdefault(stack[-1] if stack else None, [])
                order.append((depth, segment)), layer.append(segment), tree.setdefault(left, [])
            else:
                errors.append((len(stack), index))
            continue
        if stack:
            iterable = itertools.chain(enumerate(stack), errors)
            return order, tree, sorted(iterable, key=operator.itemgetter(1))
        return order, tree, errors

    @classmethod
    def verify(cls, tree, ordered, index=None):
        '''Verify a `tree` of character ranges against a mutable `ordered` list of ranges.'''
        ok = True
        for item in tree.get(index, []):
            start, stop = item
            if start in tree:
                ok = ok and cls.verify(tree, ordered, start)
            depth, slice = ordered.pop(0)
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

    @classmethod
    def duplicates(cls, string, order):
        '''Using the given `string` with the ordered segments in `order`, return a dictionary containing each index and the segments it matches with.'''
        collection = {}

        # find all the unique segments within the string so that we can reduce
        # the amount of work we'll need to do when we need to transform it.
        [collection.setdefault(string[left : right], []).append((depth, (left, right))) for depth, (left, right) in order]

        # use our collection to build a lookup table for each and every segment. each
        # value in the table will reference the same list if they're the same string.
        iterable = itertools.chain(*(segments for _, segments in collection.items()))
        return {left : collection[string[left : right]] for left, right in map(operator.itemgetter(-1), iterable)}

    @classmethod
    def unique(cls, duplicates):
        '''Process a dictionary of `duplicates` and yield each unique segment in order from deepest to most shallow.'''
        depths, unique = {}, {id(items) : index for index, items in duplicates.items()}
        [depths.setdefault(max(map(operator.itemgetter(0), duplicates[index])), []).append(index) for _, index in unique.items()]

        # iterate through each depth from the deepest to the most shallow,
        # in order to yield its index and a sample segment of the string.
        for depth in sorted(depths)[::-1]:
            for index in depths[depth]:
                _, segment = duplicates[index][-1]
                yield segment
            continue
        return

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
        '''Return a list of ranges, a tree, and a list of tuples for the errors when parsing the given `tokens` out of `string`.'''
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
                depth, layer = len(stack), tree.setdefault(stack[-1] if stack else None, [])
                order.append((depth, segment)), layer.append(segment), tree.setdefault(locations[token].pop(), []), owner.pop()
            elif token in capture:
                segment = index, index + length
                tree.setdefault(owner[-1], []).append(segment)
            else:
                error = depth, segment = len(stack), (index, index + length)
                errors.append(error)
            continue

        # If the stack isn't empty, then we encountered some mismatched pairs
        # (errors) in the beginning of the string and we need to return them first.
        if stack:
            iterable = ([(index, index + len(token)) for index in locations[token]] for token in open)
            leftover = {left : (left, right) for left, right in itertools.chain(*iterable)}

            # Eat the cost of a sort to ensure the errors are ordered by position. This is
            # just in case someone wants to use the depth from the order and errors to repair
            # the nesting issues in the tree. This is an error handling case anyways...
            iterable = ((depth, leftover[index]) for depth, index in enumerate(stack))
            unsorted = [item for item in iterable] + errors
            return order, tree, sorted(unsorted, key=operator.itemgetter(1))
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
    _declaration_scopes = { 'private: ', 'protected: ', 'public: ' , '[thunk]: ', '[thunk]:private: ', '[thunk]:protected: ', '[thunk]:public: ' }

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
            parameters = [item.replace(' ', '').replace(' *', '_ptr') for item in cls.parameters(parameters[+1 : -1])]

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
        '__unknown': {idaapi.CM_CC_UNKNOWN, idaapi.CM_CC_INVALID},

        # XXX: __usercall is special and we interpret it as either >= CM_CC_MANUAL or
        #      > CM_CC_SWIFT on newer versions, but excluding CM_CC_GOLANG if it exists.
        '__usercall': {cc & idaapi.CM_CC_MASK for cc in range(idaapi.CM_CC_SWIFT if hasattr(idaapi, 'CM_CC_SWIFT') else getattr(idaapi, 'CM_CC_MANUAL', 0x90), 0x100)},
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
        '__unknown': ['unknown'],

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

    # if CM_CC_SWIFT is defined (8.3), then add it and remove it
    # from __usercall sorta like how we handle CM_CC_GOLANG.
    if hasattr(idaapi, 'CM_CC_SWIFT'):
        available['__swiftcall'] = idaapi.CM_CC_SWIFT
        choice['__swiftcall'] = {idaapi.CM_CC_SWIFT}
        choice['__usercall'] -= {idaapi.CM_CC_SWIFT}
        aliases['__swiftcall'] = ['swift', 'swiftcall']

    # now we'll just do some functional tricks to update our
    # list of choices and mappings with each of their aliases.
    # XXX: we need a lambda to capture our dicts because python devers are
    # retarded and they couldn't figure out how to avoid leaking locals.
    # this is discussed in python/cpython#47942, but i'm not holding my breath.
    (lambda choice, iterable: [functools.reduce(utils.freverse(choice.setdefault), aliases, choice.get(key, {key})) for key, aliases in iterable])(choice, aliases.items())
    (lambda available, iterable: [functools.reduce(utils.freverse(available.setdefault), aliases, available.get(key, key)) for key, aliases in iterable])(available, aliases.items())

    # collect a inverted table that we can use to map the CM_CC_ value to a string.
    descriptions = (lambda choice, aliases: {value : key for value, key in itertools.chain(*(zip(choice[key], [key] * len(choice[key])) for key in choice if key in aliases or key in {'void'}))})(choice, aliases)

    @classmethod
    def matches(cls, *conventions):
        '''Return a closure that when compared against an ``idaapi.CM_CC_*`` code will return true if matching one of the user's `conventions`.'''
        iterable = (cls.choice.get(convention, {convention}) for convention in conventions)
        result = functools.reduce(operator.or_, iterable, {empty for empty in []})
        return functools.partial(operator.contains, result)

    @classmethod
    def get(cls, convention):
        '''Return the ``idaapi.CM_CC_*`` code for the specified `convention` given as an integer or a string.'''
        result = cls.available.get(convention, convention)
        if isinstance(result, types.integer) and result & idaapi.CM_CC_MASK == result:
            return result
        cclookup = {item for item in cls.available if isinstance(item, types.string) and item.startswith('__')}
        raise internal.exceptions.InvalidParameterError(u"{:s}.get({!r}) : The convention that was specified ({:s}) is not one of the known types ({:s}).".format('.'.join([__name__, cls.__name__]), convention, "{:d}".format(convention) if isinstance(convention, types.integer) else "{!r}".format(convention), ', '.join(cclookup)))

    @classmethod
    def describe(cls, code):
        '''Return the given `code` as a string describing the calling convention it represents.'''
        if code in cls.descriptions:
            return cls.descriptions[code]
        elif code & idaapi.CM_CC_MASK == code:
            return '__unknown' if code == idaapi.CM_CC_UNKNOWN else "__unknown({:d})".format(code >> 4)
        return "__error({:d})".format(code)

    @classmethod
    def has(cls, code):
        '''Return whether the given `code` is an available calling convention.'''
        return code in cls.descriptions

    @classmethod
    def general(cls, code):
        '''Return whether the given `code` is a general calling convention used by the configured compiler.'''
        return not(code in cls.choice['__usercall']) if code in cls.descriptions else False

    @classmethod
    def unknown(cls, code):
        '''Return whether the given `code` represents an invalid or unknown calling convention.'''
        return code in {idaapi.CM_CC_INVALID, idaapi.CM_CC_UNKNOWN}

    @classmethod
    def variable(cls, code):
        '''Return whether the given `code` is a calling convention containing a variable number of arguments.'''
        return code in {idaapi.CM_CC_ELLIPSIS, idaapi.CM_CC_SPECIALE}

    @classmethod
    def user(cls, code):
        '''Return whether the given `code` is a user-specified calling convention.'''
        return code in cls.choice['__usercall']

class mangled(object):
    """
    This class processes a mangled symbol in a number of
    ways. It is intended as a base class and provides
    general functionality to infer information from a
    mangled and demangled symbol.
    """

    # First we need a classmethod that can be used to identify the type
    # of mangled name that works independent of the disassembler version.
    @classmethod
    def __type_alternative__(cls, string):
        '''Return the type of the mangled `string` as either ``idaapi.MANGLED_DATA``, ``idaapi.MANGLED_CODE``, or ``idaapi.MANGLED_UNKNOWN``.'''
        string = idaapi.demangle_name(utils.string.to(string), 0x06000207)  # MNG_NOPOSTFC | MNG_PTRMASK | MNG_IGN_ANYWAY | MNG_IGN_JMP
        return cls.MANGLED_CODE if string[-1:] == ')' else cls.MANGLED_DATA if string else cls.MANGLED_UNKNOWN

    MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
    type = staticmethod(utils.fcompose(utils.string.to, idaapi.get_mangled_name_type)) if hasattr(idaapi, 'get_mangled_name_type') else __type_alternative__

    # Now a staticmethod that's the gateway to our disassembler api.
    decode = staticmethod(utils.fcompose(utils.fpack(utils.fmap(utils.fcompose(operator.itemgetter(0), utils.string.to), utils.fcompose(operator.itemgetter(1), int))), utils.funpack(idaapi.demangle_name2 if hasattr(idaapi, 'demangle_name2') else idaapi.demangle_name), utils.string.of))

    # This is a list of all of the types known by the disassembler's COMP_MS(1) compiler demangler.
    #itertools.chain(*(map(fmt, string.ascii_uppercase + string.digits) for fmt in ["{:s}".format, "_{:s}".format, "__{:s}".format]))
    _declaration_types = [
        'signed char',
        'char',
        'unsigned char',
        'short',
        'unsigned short',
        'int',
        'unsigned int',
        'long',
        'unsigned long',
        '__segment',
        'float',
        'double',
        'long double',
        'void',
        '__int8',
        'unsigned __int8',
        '__int16',
        'unsigned __int16',
        '__int32',
        'unsigned __int32',
        '__int64',
        'unsigned __int64',
        '__int128',
        'unsigned __int128',
        'bool',
        'char8_t',
        'char16_t',
        'char32_t',
        'wchar_t',
        'schar',
        'char',
        'uchar',
        'short',
        'ushort',
        'int',
        'uint',
        'long',
        'ulong',
        '__segment',
        'float',
        'double',
        'long double',
        'void',
        '__int8',
        'unsigned __int8',
        '__int16',
        'unsigned __int16',
        '__int32',
        'unsigned __int32',
        '__int64',
        'unsigned __int64',
        '__int128',
        'unsigned __int128',
        'bool',
        'char8_t',
        'char16_t',
        'char32_t',
        'wchar_t',
    ]

    _declaration_scopes = {
        'private:',
        'protected:',
        'public:',
        '[thunk]:',
        '[thunk]:private:',
        '[thunk]:protected:',
        '[thunk]:public:',
    }

    _declaration_specifiers = {
        '__declspec(dllimport)',    # "__imp_" prefix
        '__declspec(dllexport)',
        'declspec(dllimport)',
        'declspec(dllexport)',
        '`non-virtual thunk to\'',
        '`virtual thunk to\'',
        '`covariant return thunk to\'',
        'inline', 'virtual', 'explicit', 'static',
    }

    _declaration_conventions = (lambda candidates: {item for item in candidates if isinstance(item, internal.types.string) and item.startswith('__')})(convention.choice)

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

        # XXX: IDA's demangler seems to swap the operator symbols around, so
        #      we include both in case they decide to fix it or leave it as-is.
        'operator=!':           'notequal',
        'operator=<':           'lessequal',
        'operator=>':           'greaterequal',

        'operator=+':           'add_assign',
        'operator=-':           'subtract_assign',
        'operator=*':           'multiply_assign',
        'operator=/':           'divide_assign',
        'operator=%':           'remainer_assign',
        'operator=<<':          'shiftleft_assign',
        'operator=>>':          'shiftright_assign',

        'operator=&':           'band_assign',
        'operator=|':           'bor_assign',
        'operator=^':           'bxor_assign',
    }

    # These flags seem to be required on earlier versions of the disassembler.
    __required_flags = getattr(idaapi, 'MNG_IGN_ANYWAY', 0x02000000) | getattr(idaapi, 'MNG_IGN_JMP', 0x04000000)

    def __init__(self, symbol, mask, Ftransform=None):
        '''Initialize an object for the mangled `symbol` using the flags specified by `mask`.'''
        string, order, _, errors = self.__init_mangled__(symbol, mask, Ftransform)
        self.__duplicates__ = {} if errors else token.duplicates(string, order)

    def __init_mangled__(self, symbol, mask, Ftransform=None):
        '''Initialize an object for the mangled `symbol` using the flags specified by `mask`.'''
        self.__encoded = encoded = symbol
        attempt = encoded if self.type(encoded) == self.MANGLED_UNKNOWN else self.decode(encoded, self.__required_flags | mask)
        if not attempt:
            cls = self.__class__
            raise internal.exceptions.DisassemblerError(u"{:s}(\"{:s}\", {:#x}{:s}) : Unable to demangle the specified symbol (type {:d}) using the disassembler.".format('.'.join([__name__, cls.__name__]), utils.string.escape(symbol, '"'), mask, '' if Ftransform is None else utils.string.kwargs({'Ftransform': utils.pycompat.fullname(Ftransform)}), self.type(symbol)))
        decoded = self.__extract_specifiers(self.__extract_scope(attempt))
        transformed = Ftransform(decoded) if Ftransform else decoded
        self.__decoded = transformed
        self.tokens = tokens = self.tokens[:] if hasattr(self, 'tokens') else []
        order, result, errors = token.parse(transformed, tokens)
        self.__tree__, self.__mangled = result, True if errors else False
        return transformed, order, result, errors

    def __extract_specifiers(self, string, breaking_characters={string[-1:] for string in _declaration_specifiers if string[-1:] not in _string.ascii_letters}, specifier_tokens={string for string in _declaration_specifiers if string[-1:] in _string.ascii_letters}):
        '''Remove a declaration specifier "__declspec" from the beginning of the unmangled `string` if it exists.'''
        index, _ = next(token.indices(string, breaking_characters), (-1, None)) if len(breaking_characters) > 1 else (string.find(*breaking_characters), 1)

        point = 1 + index
        if string[:point] in self._declaration_specifiers:
            self.__declaration_specifier = string[:point]
            return string[point:].lstrip()

        # try the whitespace next...
        index = string.find(' ')
        if 0 <= index and string[:index] in self._declaration_specifiers:
            self.__declaration_specifier = string[:index]
            return string[index:].lstrip()

        # ...and then we give up.
        self.__declaration_specifier = ''
        return string

    def __extract_scope(self, string):
        '''Remove a scope from the beginning of an unmangled `string` if it exists.'''
        point = 1 + string.find(': ')
        if string[:point] in self._declaration_scopes:
            self.__declaration_scope = string[:point]
            return string[point:].lstrip()

        self.__declaration_scope = ''
        return string

    @property
    def encoded(self):
        '''Return the mangled string before it was decoded.'''
        return self.__encoded

    @property
    def string(self):
        '''Return the decoded string after being demangled.'''
        return self.__encoded if self.__mangled else self.__decoded

    @property
    def scope(self):
        '''Return the scope of the decoded string after being demangled.'''
        return self.__declaration_scope

    @property
    def specifier(self):
        '''Return the declaration specifier of the decoded string after being demangled.'''
        return self.__declaration_specifier

    def has(self, index):
        '''Return whether the specified `index` contains tokens inside of it.'''
        return index in self.__tree__

    def branch(self, index):
        '''Return a list of the segments within the demangled string at the specified `index`.'''
        index, _ = index if isinstance(index, tuple) else (index, index)
        return self.__tree__.get(index, [])

    def name(self):
        '''Yield the name and a selection for the template parameters belonging to each component of the name from the decoded string.'''
        raise NotImplementedError

    def result(self):
        '''Return the type from the decoding string after being demangled.'''
        raise NotImplementedError

class function(mangled):
    """
    This class processes a mangled function name in a number of ways
    and is specific to the demangler that the disassembler provides.
    After the name has been demangled and lexed into its segments,
    some of the attributes about the demangled function can be inferred.

    This class does not implement a full parser (for performance reasons),
    or a full demangler to avoid having to maintain them for all of
    the compilers supported by the disassembler.
    """
    tokens = ['()', '<>', '[]', '{}', "`'", ' ', ',', '*', '&', ['::']]

    # Default flags that we'll use for demangling a function name.
    flags = [
        getattr(idaapi, 'MNG_NOPTRTYP', 0x00000007),    # fear, near, __ptr64 : no way to keep ptr64

        getattr(idaapi, 'MNG_ZPT_SPACE', 0x00400000),
        getattr(idaapi, 'MNG_SHORT_S', 0x00100000),     # signed int -> sint
        getattr(idaapi, 'MNG_SHORT_U', 0x00200000),     # unsigned int -> uint

        #getattr(idaapi, 'MNG_NOECSU', 0x00002000),     # class/struct/union/enum : decided to keep this.
        #getattr(idaapi, 'MNG_NOSTVIR', 0x00001000),    # static/virtual : decided to keep this.
        getattr(idaapi, 'MNG_NOTHROW', 0x00000800),
        getattr(idaapi, 'MNG_NOPOSTFC', 0x00000200),    # const suffix

        getattr(idaapi, 'MNG_NOCLOSUR', 0x00008000),    # __closure
        getattr(idaapi, 'MNG_NOUNALG', 0x00010000),     # __unaligned
        getattr(idaapi, 'MNG_NOMANAGE', 0x00020000),    # managed underscores
    ]

    # These operators have unnested spaces. So if we want to preserve parameter
    # information it's just easier to join them together into a single token.
    _declaration_operators_with_spaces = {
        'operator new':         'new',
        'operator delete':      'delete',
        'operator new[]':       'new_array',
        'operator delete[]':    'delete_array',
        'operator co_await':    'coro_await',

        ' *':                   'pointer_member',   # this is special, like "operator {type:s} *"
        'operator""':           'doublequote',      # this is another special-case, 'operator"" {type:s}'
    }

    # Add all of the known "basic" type operators...
    # FIXME: technically any kind of type can be declared after this and we really
    #        should be distinguishing the complex type for the operator first...
    _declaration_operators_with_spaces.update({"operator {:s}".format(_type) : '_'.join(['cast', _type.replace(' ', '_')]) for _type in mangled._declaration_types})

    # These operators will always return an error due to them using the same tokens
    # as a template which will be unbalanced without having a full parser. Thus this
    # dictionary is for identifying fixing the things that we know will error.
    _declaration_operators_with_errors = {

        # we expect these operators to have exactly one error.
        'operator->':           'pointer',
        'operator->*':          'pointermember',

        'operator<':            'less',
        'operator<=':           'lessequal',
        'operator>':            'greater',
        'operator>=':           'greaterequal',

        # these operators should always have two errors.
        'operator<<':           'shiftleft',
        'operator>>':           'shiftright',
        'operator<<=':          'shiftleftassign',
        'operator>>=':          'shiftrightassign',

        # just in case the demangler wants to switch these around.
        'operator=<<':          'shiftleftassign',

        'operator=>>':          'shiftrightassign',

        # this operator is...perfect.
        #'operator<=>':          'spaceship',
    }

    _declaration_qualified_operator = {' ' + qualifier : 1 + len(qualifier) for qualifier in {'const', 'volatile', '__unaligned', 'restrict', 'far', 'near', '*', '&'}}

    # Miscellaneous tuples that cache the different parts of a prototype.
    __cache_prototype = __cache_result_and_convention = __cache_parameters = ()
    __flags = functools.reduce(operator.or_, flags, getattr(idaapi, 'MNG_NOPTRTYP', 7))

    def __init__(self, mangled):
        if self.type(mangled) != self.MANGLED_CODE:
            cls = self.__class__
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}(\"{:s}\") : Unable to demangle the given string as a function due to it being a non-code type ({:d}).".format('.'.join([__name__, cls.__name__]), utils.string.escape(mangled, '"'), self.type(mangled)))

        # Figure out the default flags that are needed to demangle just the name. Some
        # compilers chosen by the disassembler will return None wihout the correct flags.
        MNG_IGN_JMP, MNG_NODEFINIT, MNG_NOECSU = (getattr(idaapi, attribute, default) for attribute, default in [('MNG_IGN_JMP', 0x04000000), ('MNG_NODEFINIT', 0x00000008), ('MNG_NOECSU', 0x00002000)])
        name_flags = functools.reduce(operator.or_, [MNG_IGN_JMP, MNG_NODEFINIT], self.__flags & 0x00F00000)

        # First we need to do a "test" demangle to determine if the "'" token has two
        # meanings. This only happens with the "`'" segments and always ends in "''".
        just_name = self.decode(mangled, name_flags)
        if not just_name:
            logging.info(u"{:s}(\"{:s}\") : Unable to demangle symbol using {:s}(\"{:s}\", {:#0{:d}x}).".format('.'.join([__name__, self.__class__.__name__]), utils.string.escape(mangled, '"'), '.'.join(item.__name__ for item in [idaapi, idaapi.demangle_name] if hasattr(item, '__name__')), utils.string.escape(mangled, '"'), name_flags, 2 + 8))
            just_name = self.__init__guess_name(mangled, self.__flags)
        if not just_name:
            raise internal.exceptions.AssertionError(u"{:s}(\"{:s}\") : Unable to parse out the name from the demangled symbol returned by {:s}(\"{:s}\", {:#0{:d}x}).".format('.'.join([__name__, self.__class__.__name__]), utils.string.escape(mangled, '"'), '.'.join(item.__name__ for item in [idaapi, idaapi.demangle_name] if hasattr(item, '__name__')), utils.string.escape(mangled, '"'), self.__flags, 2 + 8))
        operator_string = 'operator'
        result = just_name.rfind(operator_string)
        index = result if result >= 0 else len(just_name)
        just_operator = just_name[index:]
        result = just_name.rfind(' ')
        index = result if result >= 0 else len(just_name)
        just_space = just_name[index:]

        # If we cleanly extracted the operator and it's in our dictionary of known
        # operators, then save its transformation so that we can replace it later.
        clean_operator = self._declaration_operators.get(just_operator, '')

        # Now we need to do some special-case checks for the single-quote meanings, operator
        # double-meaning for "<" or ">", operators with spaces, anything with expected errors.
        single_quote, double_quote = just_name.endswith("''"), just_operator.startswith('operator"" ')
        expected_errors = just_operator in self._declaration_operators_with_errors
        expected_spaces = just_operator in self._declaration_operators_with_spaces
        qualified_with_spaces = just_space in self._declaration_qualified_operator or (not any([single_quote, expected_spaces, single_quote, double_quote]) and just_operator.startswith(('operator ', 'operator"" ')))
        null_parameters = just_name[-1:] in {'{', '}'}

        # Before decoding, we need to build a dictionary of strings that we're
        # going to expect so that we can handle them during parsing.
        expected_operators = {}
        if expected_errors:
            expected_operators[just_operator] = "operator_{:s}".format(self._declaration_operators_with_errors[just_operator])
        if expected_spaces:
            expected_operators[just_operator] = "operator_{:s}".format(self._declaration_operators_with_spaces[just_operator])

        # We also need to specially handle the situation where quotes or unbalanced characters can
        # interfere with the name. We accomplish this by transforming the string prior to parsing.
        kwargs = {}
        if single_quote or double_quote:
            kwargs['Ftransform'] = functools.partial(self.__clean_quotes, len(just_operator) if double_quote else 0)
        elif expected_operators:
            kwargs['Ftransform'] = functools.partial(self.__clean_unbalanced, len(just_operator), expected_operators)
        elif null_parameters:
            kwargs['Ftransform'] = functools.partial(self.__clean_parameters, just_name[1 + just_name.rfind(' '):])
        elif qualified_with_spaces and not(self.__flags & MNG_NOECSU):
            kwargs['Ftransform'] = functools.partial(self.__guess_qualified_operator, just_operator)
        elif qualified_with_spaces and self.__flags & MNG_NOECSU:
            kwargs['Ftransform'] = functools.partial(self.__clean_qualified_operator, len(just_operator))

        # If we were able to extract the operator cleanly, then we can just
        # replace it. If we don't have a match, then it's definitely typed.
        elif clean_operator:
            kwargs['Ftransform'] = functools.partial(self.__clean_replacement, just_operator, "operator_{:s}".format(clean_operator))
        elif just_operator:
            pass    # FIXME: this should probably be implemented at some point.

        # That should be all of the special cases, so now we just
        # need to decode the mangled symbol and parse it.
        decoded, order, tree, errors = self.__init_mangled__(mangled, self.__flags, **kwargs)

        # If we encountered some errors, then complain about it so
        # that the user will know why we can't do shit with it.
        if errors:
            just_operator, target, segment = _, _, (left, right) = self.__init__busted_operator(decoded)
            expected_operators[just_operator] = decoded[left : right]
            Ftransform = functools.partial(self.__clean_segment, segment, "operator_{:s}{:s}".format(self._declaration_operators_with_errors[just_operator], target))
            decoded, order, tree, errors = self.__init_mangled__(mangled, self.__flags, Ftransform=Ftransform)
            self.__operator_target = just_operator, target

        # If there weren't any errors, then there isn't a special case and we should be fine.
        else:
            self.__operator_target = ()

        # If we still have an error, then it's because the prototype in unparsable (by us).
        if errors:
            cls = self.__class__
            logging.warning(u"{:s}(\"{:s}\") : Unable to parse the mangled string \"{:s}\" after it was decoded to \"{:s}\".".format('.'.join([__name__, cls.__name__]), utils.string.escape(mangled, '"'), utils.string.escape(mangled, '"'), utils.string.escape(decoded, '"')))

        # If we already figured out what operator it is, then store that too.
        self.__operator = just_operator if double_quote or expected_operators or qualified_with_spaces or clean_operator else ''

        # Identify any duplicate segments in case we need to translate this string.
        self.__duplicates__ = {} if errors else token.duplicates(decoded, order)

    def __init__guess_name(self, mangled, flags):
        '''Attempt to guess the function name from the decoded string specified by `mangled`.'''
        decoded = self.decode(mangled, flags)
        if not decoded:
            cls = self.__class__
            raise internal.exceptions.DisassemblerError(u"{:s}(\"{:s}\", {:#x}) : Unable to demangle the specified symbol (type {:d}) using the disassembler.".format('.'.join([__name__, cls.__name__]), utils.string.escape(mangled, '"'), flags, self.type(mangled)))

        # We pre-parse all of the tokens, just so we can pass the tree directly
        # to extract.prototype and assume that it correctly figured out the name.
        order, result, errors = token.parse(decoded, self.tokens)
        result_and_convention, name, parameters, qualifiers = extract.prototype(result, decoded)

        # Now we should have the range and segments for the name. Unpack the
        # range and use it with the decoded string to return the proper name.
        (left, right), segments = name
        return decoded[left : right]

    def __init__busted_operator(self, decoded):
        '''Initialize the class for a typed operator in `decoded` which contains unbalanced symbols.'''
        reversed = decoded[::-1]

        # I realized during testing of the `extract` namespace, that it makes more sense to
        # do the tokenization in reverse, similar to the clockwise spiral rule, but figured
        # I could still get away with it since I wanted to iterate through the parameters
        # left-to-right for all types without having to hold onto a list. Now I'm realizing
        # that was a mistake. Oh well..
        order, rtree, errors = token.parse(reversed, [token[::-1] if len(token) > 1 else token for token in self.tokens])

        # Start at the last index and find the very first point that references
        # a segment in the tree. If none of them are in the tree, then we can
        # make an assumption where the operator is actually located.
        iterable = ((index, segment) for index, (_, segment) in enumerate(errors[::-1]))
        error_index = next((1 + index for index, (point, _) in iterable if point in rtree), 0)

        # The first item should definitely be a type specifier of some sort which is bounded
        # by "<>". Once we confirm that, then we can check to see if it's an error operator.
        iterable = ((index, reversed[left : right]) for index, (left, right) in enumerate(rtree.get(None, [])))
        index = next((1 + index for index, rstring in iterable if rstring[-1:] + rstring[:1] == '<>'), 0)
        assert(index), decoded
        rsegments = rtree[None][:index]

        # If we didn't find an error point within the tree, then we know that our operator
        # and its target are within the first layer of the tree and we can simply extract it.
        left, point = rsegments[-1]
        if not error_index:
            right, _ = rtree[None][index] if index < len(rtree[None]) else (len(reversed), None)
            operator, target = reversed[point : right][::-1], reversed[left : point][::-1]

        # Otherwise, this is probably a operator cast of some kind and we need to use
        # the determined error point as a pivot between the operator and its target.
        else:
            _, (error_point, _) = errors[-error_index]
            right, _ = rtree[error_point][0]
            operator, target = reversed[point : right][::-1], reversed[left : point][::-1]

        # Now unless our demangled type is seriously busted we should have
        # the segment containing the type that the operator is targeting.
        nsegment = len(decoded) - right, len(decoded) - left
        return operator, target, nsegment

    def __clean_quotes(self, operator_length, string):
        '''Return a transformed `string` with its single-quotes or double-quotes fixed using the given `operator_length`.'''
        dquote_string = 'operator"" '

        # if we found some double-quotes, then we'll just use "{}" to nest the type.
        if operator_length:
            left = string.rindex(dquote_string)
            assert(left >= 0), string
            middle, right = left + len(dquote_string), left + operator_length
            return string[:left] + 'operator""{' + string[middle : right] + '}' + string[right:]

        # otherwise we have single-quotes with two different semantics,
        # and we need to scan backwards to find it and then fix it.
        [operator, parameters] = string.rsplit("''", 1)
        index = operator.rindex("'")
        return operator[:index] + '{' + operator[1 + index:] + "}'" + parameters

    def __clean_unbalanced(self, operator_length, replacements, string):
        '''Return a transformed `string` with its unbalanced symbols replaced using `operator_length` and a dictionary of `replacements`.'''
        keyword = 'operator'
        left = string.rindex(keyword)
        assert(left >= 0), string
        assert(string[max(0, left - 1) : left + len(keyword)] in {':operator', ' operator', 'operator'}), string
        right = left + operator_length
        return string[:left] + replacements[string[left : right]] + string[right:]

    def __clean_segment(self, segment, replacement, string):
        '''Return a transformed `string` with the specifed `segment` replaced with `replacement`.'''
        left, right = segment
        return string[:left] + replacement + string[right:]

    def __clean_parameters(self, name, string):
        '''Return a transformed `string` with empty parameters added after the given prototype `name`.'''
        needs_parentheses = string[-len(name):] == name
        return string + '()' if needs_parentheses else string

    def __clean_qualified_operator(self, operator_length, string):
        keyword = 'operator'
        left = string.rindex(keyword)
        assert(left >= 0), string
        assert(string[max(0, left - 1) : left + len(keyword)] in {':operator', ' operator', 'operator'}), string

        # We probably should walk backwards and tally up the qualifiers, but it's
        # easier to transform the entire operator with braces and eat the cost later.
        type = string[left + len(keyword) + 1 : left + operator_length]
        return string[:left] + "operator{{{:s}}}".format(type) + string[left + operator_length:]

    def __guess_qualified_operator(self, operator_name, string):
        keyword = 'operator'
        start = string.rindex(keyword)
        assert(start >= 0), string
        assert(string[max(0, start - 1) : start + len(keyword)] in {':operator', ' operator', 'operator'}), string

        # FIXME: This is pretty inefficient since we're doing this twice, and we
        #        essentially repeat the exact same logic later for a third time.
        height, _, errors = token.parse(operator_name, self.tokens)
        assert(not(errors)), operator_name
        count = sum(1 for index, segment in height if index == 0)

        height, _, errors = token.parse(string, self.tokens)
        assert(not(errors)), string
        filtered_heights = [segment for index, segment in height if index == 0]
        point, right = filtered_heights.pop()
        parameters = string[point : right]
        assert(parameters[:1] + parameters[-1:] in {'()'}), string

        target = string[start + len(keyword) + 1 : point]
        return string[:start] + "operator{{{:s}}}".format(target) + string[point:]

    def __clean_replacement(self, keyword, replacement, string):
        '''Return a transformed `string` with the specifed `keyword` substituted by `replacement`.'''
        point = string.rindex(keyword)
        return string[:point] + replacement + string[point + len(keyword):]

    @property
    def __prototype_components(self):
        '''Return a cached tuple containing the extracted components of a function prototype.'''
        if self.__cache_prototype:
            return self.__cache_prototype
        result_and_convention, name, parameters, qualifiers = extract.prototype(self.__tree__, self.string)
        result = self.__cache_prototype = result_and_convention, name, parameters, qualifiers
        return result

    @property
    def qualifiers(self):
        '''Return a list of the qualifiers that follow the function prototype.'''
        _, _, _, qualifiers = self.__prototype_components
        return [self.string[left : right] for left, right in qualifiers]

    @property
    def __result_and_convention(self):
        '''Return a cached tuple containing the extracted components of the result and calling convention.'''
        if self.__cache_result_and_convention:
            return self.__cache_result_and_convention

        # Unpack the result and convention from the components of the prototype, and
        # extract the segment that contains the the very last token.
        result_and_convention, _, _, _ = self.__prototype_components
        result_untrimmed, convention_candidate = extract.ending(self.string, *result_and_convention)

        # If our ending token matches a convention exactly, then track its boundaries
        # and assign a tuple that splits up the result token from the convention segment.
        (left, right), segments = convention_candidate
        if not segments and self.string[left : right] in self._declaration_conventions:
            result_trimmed = extract.trimmed(self.string, *result_untrimmed)
            result = self.__cache_result_and_convention = result_trimmed, (left, right)
            return result

        # If the convention segment represents a string that starts with "__",
        # then just warn the user about it since it might be a candidate.
        if self.string[left : right].startswith('__'):
            cls, result = self.__class__, ()
            logging.warning(u"{:s}.__result_and_convention: Ignoring candidate for calling convention \"{:s}\" due to it being unknown.".format('.'.join([__name__, cls.__name__]), utils.string.escape(self.string[left : right], '"')))

        # Otherwise, there is no convention and we store an empty segment for it.
        (left, right), _ = result_and_convention
        result = self.__cache_result_and_convention = result_and_convention, (right, right)
        return result

    @property
    def convention(self):
        '''Return the calling convention of the decoded string if available.'''
        _, (left, right) = self.__result_and_convention
        return self.string[left : right]

    @property
    def result(self):
        '''Return the result of the decoded string if available.'''
        result, _ = self.__result_and_convention
        return qualified_declaration_or_function_pointer(self.__tree__, self.string, *result)

    @property
    def name(self):
        '''Return a list for each name component from the decoding string containing both the name and segment for the component's template parameters.'''
        _, prototype_name, _, _ = self.__prototype_components
        return fullname(self.__tree__, self.string, *prototype_name)

    @property
    def operator(self):
        '''Return the operator for the decoded prototype if it describes one.'''
        if self.__operator:
            return self.__operator

        # Unpack the name and extract all of its components into a list.
        _, prototype_name, _, _ = self.__prototype_components
        components = [item for item in token.split(self.string, *prototype_name, tokens={'::'})]

        # If the number of components are less than 2, then we just need
        # to check that the last token is a known operator or not.
        if len(components) < 2:
            return self.__extract_operator(components) if components else ''

        # All we need to do is check if the last 2 components are exactly
        # the same. If they are, it's a constructor or a destructor.
        [namespace, method] = (self.string[left : right] for (left, right), _ in components[-2:])
        if namespace == method:
            return 'constructor'

        elif '~' + namespace == method:
            return 'destructor'

        return self.__extract_operator(components)

    def __extract_operator(self, components):
        '''Return the operator from the selections given by the list of `components` if available.'''
        if not components: return ''
        (left, right), items = components[-1]
        string = self.string[left : right]

        # If it's a known operator, then we can just return it.
        if string in self._declaration_operators:
            return string

        # If it's backticked then we can return that too.
        elif string[:1] + string[-1:] == "`'":
            return string

        # If it's backticked, but also braced then we return it as well.
        elif string[:1] in '`' and len(items) and (lambda string: string[:1] + string[-1:] in '{}')(string[slice(*items[-1])]):
            return string

        # Otherwise, it's nothing we know about and we use a string check.
        return string if string.startswith('operator') else ''

    def details(self):
        '''Return a tuple containing the unpacked details contained by the operator or backticked function name.'''
        operator_name = self.operator
        _, name, _, _ = self.__prototype_components
        (start, stop), segments = name
        iterable = (1 + index for index, (left, right) in enumerate(segments[::-1]) if self.string[left : right] == '::')
        index = next(iterable, 0)
        (_, point) = segments[-index] if index else (start, start)

        # If we're a backticked operator with a brace, then our operator is a
        # vcall or similar. So, we need the last 2 segments of the name...
        if operator_name[:1] + operator_name[-1:] == '`}':
            [operator_name, braces] = segments[-2:]

            # The braces segment can simply be treated as ','-delimited parameters.
            iterable = extract.parameters(self.__tree__, self.string, braces)
            parameters = [self.string[left : right] for (left, right), _ in iterable]

            # Now we can just return a tuple prefixed with the operator.
            left, right = operator_name
            return self.string[left : right], parameters

        # If it's a known operator, then this is likely parameterized with angles.
        elif operator_name in self._declaration_operators:
            [(left, right)] = segments[-1:] if len(segments) else [(start, start)]
            if right != stop or right - left < len(operator_name):
                return operator_name, []
            contents, ignored = self.string[left : right], {' ', ''}
            assert(contents[:1] + contents[-1:] == '<>'), contents
            iterable = extract.parameters(self.__tree__, self.string, (left, right))
            parameters = [self.string[left : right].lstrip() for (left, right), _ in iterable]
            return operator_name, parameters

        # FIXME: These operators_with_spaces are essentially a hack, since you can
        #        technically include any kind of complex type after the operator.
        elif not segments or operator_name in self._declaration_operators_with_spaces or operator_name in self._declaration_operators_with_errors:
            return (operator_name,) if operator_name else ()

        # Otherwise, it should be a transformed operator and we can extract details from the braces.
        elif self.__operator:
            [(_, start), (point, right)] = segments[-2:] if len(segments) > 1 else [(start, start)] + segments[-1:]
            contents, ignored = self.string[point : right], {' ', ''}
            assert(contents[:1] + contents[-1:] == '{}'), contents
            trimmed, qualifiers = (point + 1, right - 1), {qualifier[1:] for qualifier in self._declaration_qualified_operator}
            declaration, qualifiers = extract.qualifiers(self.string, trimmed, self.__tree__.get(point, []), qualifiers=qualifiers)
            iterable = [self.string[left : right] for left, right in token.segments(*qualifiers)]
            (left, right), _ = declaration
            return self.string[start : point], self.string[left : right], [string for string in iterable if string not in ignored]

        # Now we should probably handle the special-case for constructors and destructors.
        elif operator_name in {'constructor', 'destructor'}:
            return operator_name,

        # If we have an operator, but it's only non-nested tokens, then there's no details.
        # FIXME: we're explicitly testing for "` (" operators here, which have details.
        elif operator_name:
            assert(operator_name[:1] + operator_name[-1:] in {"`'", "` "}), operator_name
            ignored, (start, stop) = {' '}, segments[-1] if segments else (stop, stop)
            nested = self.__tree__.get(start, [])
            if all(self.string[left : right] in ignored for left, right in nested):
                return operator_name,

            # But if there are nested tokens, then we're likely braced and containing a type.
            (left, right) = nested[-1]
            brace = self.string[left : right]
            assert(brace[:1] + brace[-1:] in {'()', '{}', "`'", '[]'})
            return operator_name, brace[1 : -1]

        # If there's no operator, then we need to check our name for what the user wants.
        [(start, stop)] = segments[-1:]
        string = self.string[start : stop]

        # If it's backticked, then the braces are within the backtick.
        if string[:1] + string[-1:] == "`'":
            segments = self.__tree__.get(start, [])
            left, right = segments[-1] if segments else (stop, stop)
            iterable = extract.parameters(self.__tree__, self.string, (left, right)) if left != right else []
            return self.string[start : left] + "'", [self.string[left : right] for (left, right), _ in iterable]

        # If we got here, then there just aren't any details for us to extract.
        return ()

    def __repr__(self):
        '''Return the internal representation of the string that contains the function name.'''
        cls = self.__class__
        return "{!s} ({:s}) {!r}".format(cls, self.operator, self.string)

    @property
    def parameters(self):
        '''Yield each parameter of the decoded string as a list of name components and qualifiers.'''
        _, _, parameters, _ = self.__prototype_components
        start, _ = parameters
        return group_parameters(self.__tree__, self.string, parameters, self.__tree__.get(start, []))

class selection(object):
    """
    This class is a base class that stores a string, a tree, and a token
    selection. Implementors of this class can add methods to extract specific
    attributes from the token and return them to the user. It also implements
    the necessary abstractions so that it can be treated like a regular string.
    """
    def __init__(self, tree, string, range, segments):
        self.__tree__, self.__string__ = tree, string
        self.__selection__ = range, segments

    def select(self, type, selection):
        return type(self.__tree__, self.__string__, *selection)

    def descend(self, type, segment):
        (start, stop) = segment
        return type(self.__tree__, self.__string__, segment, self.__tree__.get(start, []))

    @property
    def tree(self):
        return self.__tree__

    @property
    def range(self):
        range, _ = self.__selection__
        return range

    @property
    def tokens(self):
        _, tokens = self.__selection__
        return tokens

    @property
    def segments(self):
        string, iterable = self.__string__, token.segments(*self.__selection__)
        return [string[left : right] for left, right in iterable]

    @property
    def string(self):
        (left, right), _ = self.__selection__
        return self.__string__[left : right]

    def __bool__(self):
        range, _ = self.__selection__
        return operator.ne(*range)

    def __str__(self):
        (left, right), _ = self.__selection__
        return self.__string__[left : right]

    def __repr__(self):
        cls = self.__class__
        return "{!s} {:s} : {!r}".format(cls, "{:d}..{:d}".format(*self.range), self.segments)

class name_component(selection):
    '''
    This class represents the individual component of a name. A
    name component contains a string that may be potentially
    followed by template parameters.
    '''
    @property
    def __correct_selection(self):
        (start, stop), segments = self.__selection__
        candidate = (left, right) = segments[-1] if len(segments) else (stop, stop)
        string = self.__string__[left : right]
        assert(operator.eq(*candidate) or string[:1] + string[-1:] in {'<>', "`'"}), string
        if len(segments) > 1:
            cls = self.__class__
            (left, right), parameters = extract.trimmed(self.__string__, (start, left), segments[-1:])
            logging.debug(u"{:s}: Trimmed the name ({:d}..{:d}) which resulted in it residing at {:d}..{:d} and followed by its parameters ({:s}).".format('.'.join([__name__, cls.__name__]), start, stop, left, right, ', '.join("{:d}..{:d}".format(*segment) for segment in parameters)))
            return (left, right), parameters
        return (start, stop), segments

    @property
    def name(self):
        (start, stop), segments = self.__selection__
        if len(segments) > 1:
            (start, stop), segments = self.__correct_selection
        filtered = [(left, right) for left, right in segments if self.__string__[left : right] not in {' '}]
        (point, _) = filtered[-1] if filtered else (stop, stop)
        return self.__string__[start : point]

    @property
    def specifier(self):
        (start, stop), segments = self.__selection__
        if len(segments) <= 1:
            left, right = segments[-1] if segments else (stop, stop)
        else:
            _, segments = self.__correct_selection
            left, right = segments[-1] if segments else (stop, stop)

        # FIXME: if there's no name and the whole thing is a parameter, then this is not a specifier.
        string = self.__string__[left : right]
        return '' if (start, stop) == (left, right) and string[:1] + string[-1:] in {'<>'} else string

    @property
    def parameters(self):
        (start, stop), segments = self.__selection__
        string = self.__string__[start : stop]
        branch = segments[-1] if segments and string and string[-1] == '>' else (stop, stop)
        return self.descend(angle_parameters, branch)

class parameters(selection):
    __pairs__ = {}
    def __init__(self, tree, string, range, segments):
        super(parameters, self).__init__(tree, string, range, segments)
        self.__cache = [extract.trimmed(string, *selection) for selection in extract.parameters(tree, string, range, assertion=self.__pairs__)] if operator.ne(*range) else []

    @property
    def count(self):
        return len(self.cache)

    @property
    def cache(self):
        return self.__cache

    def item(self, index):
        string, selection = self.__string__, self.cache[index]
        return self.select(qualified_declaration_or_function_pointer, selection)
    __getitem__ = item

    def __repr__(self):
        cls, string, iterable = self.__class__, self.__string__, (range for range, _ in self.__cache)
        return "{!s} {:s} : {!r}".format(cls, "{:d}..{:d}".format(*self.range), [string[left : right] for (left, right) in iterable])

class angle_parameters(parameters): __pairs__ = {'<>'}
class group_parameters(parameters): __pairs__ = {'()'}
class bracket_parameters(parameters): __pairs__ = {'[]'}
class brace_parameters(parameters): __pairs__ = {'{}'}

def qualified_declaration_or_function_pointer(tree, string, range, segments):
    (start, stop) = range
    selected = string[start : stop]
    constructor = function_pointer_with_qualifiers if selected and selected[-1:] == ')' else declaration_with_qualifiers
    return constructor(tree, string, range, segments)

class function_pointer_with_qualifiers(selection):
    ignored = {' '}
    def __init__(self, tree, string, range, segments):
        super(function_pointer_with_qualifiers, self).__init__(tree, string, range, segments)
        result, convention, parameters = extract.function_pointer(string, range, segments)
        self.__cache = result, convention, parameters
        start, _ = convention
        self.__cache_convention = convention, tree.get(start, [])

    @property
    def __correct_selection_for_missing_convention(self):
        (start, stop), segments = self.__selection__

    @property
    def declaration(self):
        decl, _ = extract.qualifiers(self.__string__, *self.__selection__)
        (start, stop), _ = decl
        return self.__string__[start : stop]

    @property
    def result(self):
        (left, right), iterable = self.__cache_convention
        result, _, _ = self.__cache
        if left < right:
            return self.select(qualified_declaration_or_function_pointer, result)

        (left, right), segments = self.__selection__
        point, _ = segments[-1]
        if self.__string__[:point].endswith(' '):
            result, _ = extract.ending(self.__string__, (left, point), segments[:-1])
            return self.select(qualified_declaration_or_function_pointer, extract.trimmed(self.__string__, *result))

        result_untrimmed, _ = extract.ending(self.__string__, *result)
        (left, right), _ = result_untrimmed
        result = extract.trimmed(self.__string__, *result if left == right else result_untrimmed)
        return self.select(qualified_declaration_or_function_pointer, result)

    @property
    def parameters(self):
        _, _, parameters = self.__cache
        return self.descend(group_parameters, parameters)

    @property
    def convention(self):
        (left, right), _ = self.__cache_convention
        if left < right:
            convention, _, _ = extract.function_pointer_convention(self.__string__, *self.__cache_convention)
            left, right = convention
        return self.__string__[left : right]

    @property
    def qualifiers(self):
        (left, right), iterable = self.__cache_convention
        if left < right:
            _, symbols, _ = extract.function_pointer_convention(self.__string__, *self.__cache_convention)
        else:
            symbols = []
        iterable = (self.__string__[left : right] for left, right in symbols)
        return [string for string in iterable if string not in self.ignored]

    @property
    def name(self):
        (left, right), iterable = self.__cache_convention
        if left < right:
            _, _, name = extract.function_pointer_convention(self.__string__, *self.__cache_convention)
        else:
            (left, right), segments = self.__selection__
            point, _ = segments[-1]
            _, name = extract.ending(self.__string__, (left, point), segments[:-1])
        return self.select(fullname, name)

class declaration_with_qualifiers(selection):
    ignored = {' '}
    __modifiers__ = {'class', 'struct', 'union', 'enum', 'signed', 'unsigned'}

    @property
    def declaration(self):
        (start, stop), _ = self.__selection__
        return self.__string__[start : stop]

    @property
    def name(self):
        _, without_keyword = extract.keyword(self.__string__, *self.__selection__, keywords=self.__modifiers__)
        declaration_untrimmed, _ = extract.qualifiers(self.__string__, *without_keyword)
        declaration_trimmed = extract.trimmed(self.__string__, *declaration_untrimmed)
        return self.select(fullname, declaration_trimmed)

    @property
    def modifier(self):
        keyword, _ = extract.keyword(self.__string__, *self.__selection__, keywords=self.__modifiers__)
        return keyword

    @property
    def qualifiers(self):
        _, quals = extract.qualifiers(self.__string__, *self.__selection__)
        iterable = (self.__string__[left : right] for left, right in token.segments(*quals))
        return [string for string in iterable if string not in self.ignored]

class fullname(selection):
    delimiter = {'::'}
    def __init__(self, tree, string, range, segments):
        super(fullname, self).__init__(tree, string, range, segments)
        iterable = token.split(string, range, segments, self.delimiter)
        #self.__cache = [extract.trimmed(string, *selection) for selection in iterable]
        self.__cache = [selection for selection in iterable]

    @property
    def cache(self):
        return self.__cache

    @property
    def count(self):
        string, iterable = self.__string__, extract.name_and_template(self.__string__, *self.__selection__)
        return sum(1 for item in iterable)

    def item(self, index):
        cache = self.__cache[index]
        return self.select(name_component, cache)
    __getitem__ = item

    def name(self, index):
        (start, stop), _ = self.__cache[index]
        return self.__string__[start : stop]

class parseable(object):
    """
    This class is a base class that takes an unmangled string or instance of
    the `mangled` class and then pre-transforms all of its unique segments
    so that it can be rendered in a format that can be parsed by the disassembler
    if used as a name.

    Implementors of this class can then customize how to re-mangle an unmangled
    string so that it can be easier for a user to interpret or apply a regular
    expression to a mangled symbol name. The unique segments are cached with
    the intention that a transformation will only need to be calculated once.
    """

    # take the pair of tokens from the `function.tokens` set and turn it into
    # a O(1) lookup table that we can use to check if a string is cuddled.
    #pairs = {start : stop for start, stop in {'<>', '()', '[]', '{}', "`'"}}
    pairs = {token[:1] : token[-1:] for token in function.tokens if len(token) == 2}

    def __init__(self, string, mappings={}):
        copied = {original : transformed for original, transformed in mappings.items()}
        self.__cache__ = copied     # map of substrings to transformed substring
        self.__index__ = {}         # map of string indices to transformed substring

        # we're good friends with instances of the mangled class, because we
        # rely on it to ensure the nested parts are balanced and parseable.
        if isinstance(string, mangled):
            rendered, tree, duplicates = string.string, string.__tree__, string.__duplicates__
            self.__string__, self.__tree__, self.__duplicates__ = rendered, tree, duplicates

        # otherwise we just assume it's a string for the purposes of testing.
        else:
            order, tree, errors = token.parse(string, function.tokens)
            duplicates = token.duplicates(string, order)
            assert(not(errors)), errors
            self.__string__, self.__tree__, self.__duplicates__ = string, tree, duplicates

        # now we can identify the unique segments from our duplicates. this should
        # greatly reduce the amount of processing work we'll have to do on the string.
        iterable = token.unique(duplicates)
        self.__unique__ = [segment for segment in iterable]

        # FIXME: the __cache_unique__ method should probably be exposed to the user
        #        in some way, and this class needs to be refactored so that an
        #        implementor of it can influence the way the string gets rendered.

    def __cache_unique__(self):
        '''Process all of the unique segments within the unmangled string and cache all transformed results.'''
        result = []
        for left, right in self.__unique__:
            substring = self.__string__[left : right]
            parsed = self.send(left, substring)
            result.append(parsed)
        return result

    def render(self):
        '''Render the current string in its parseable form using any cached segments.'''
        offset, result, string = 0, [], self.__string__
        for left, key, right in token.augment(None, self.__tree__.get(None, [])):
            offset += left

            # select the current segments and append them to our result.
            lstring, rstring = string[offset - left : offset], string[offset : offset + right]
            result.append(lstring)

            # use the current key to figure out the transformed substring via one of the caches.
            transformed = self.send(key, rstring)
            result.append(transformed)
            offset += right
        return ''.join(result)

    def send(self, index, substring):
        '''Return the prior transformed string for the `substring` at the specified `index`.'''
        table, cache = self.__index__, self.__cache__

        # if index is already in our table, then we can just use it. (fast-path)
        if index in table:
            return table[index]

        # if the substring already exists in our cache, then update all its
        # indices for the fastpath, and return the transformed substring.
        elif substring in cache:
            transformed = cache[substring]
            #print(['sendsub', substring, transformed])
            iterable = (segment for depth, segment in self.__duplicates__.get(index, []))
            [table.setdefault(left, transformed) for left, right in iterable]
            return cache[substring]

        # otherwise we check if we have an index for the string inside
        # the tree and figure out how we'll need to process/transform it.
        elif index in self.__tree__:
            #print(['sendproc', index, substring])
            cache[substring] = transformed = self.process_branch(index, substring)
            return transformed

        # there's nothing we can do with this string, so return it untransformed.
        #print(['notrans', index, substring])
        return substring

    def __process_augmented(self, augmented, substring, separators={','}):
        '''Process the given `substring` using the `augmented` segments to split each of its tokens by `separators` and yield them.'''
        offset, result = 0, []
        for left, key, right in augmented:
            offset += left
            lstring, rstring = substring[offset - left : offset], substring[offset : offset + right]

            # if the key is in our tree, then it's worth checking the cache
            lstring and result.append(lstring)
            if key in self.__tree__:
                cached = self.__index__[key] if key in self.__index__ else self.__cache__[rstring] if rstring in self.__cache__ else rstring
                result.append(cached)

            # if we hit a separator, then check it against the cache and yield it.
            elif rstring in separators:
                yield ''.join(result)
                result = []

            # otherwise, there's nothing to do.
            elif rstring:
                result.append(rstring)
            offset += right

        # if there's anything left, then return it.
        offset < len(substring) and result.append(substring[offset:])
        if result:
            yield ''.join(result)
        return

    def process_nopair(self, index, substring, separators={','}):
        '''Process the uncuddled `substring` at the specified `index` split by the tokens in `separators`.'''
        assert(index in self.__tree__)
        augmented = token.augment(index, self.__tree__[index])

        joined = self.__cache__[substring] if substring in self.__cache__ else ','.join(self.__cache__.get(item, item) for item in self.__process_augmented(augmented, substring, separators=separators))
        #print(['cached', substring, joined])
        return self.__cache__.setdefault(substring, joined)

    def process_pair(self, index, substring, separators):
        '''Process the cuddled `substring` at the specified `index` split by the tokens in `separators`.'''
        assert(index in self.__tree__)
        augmented = token.augment(index, self.__tree__[index])
        pairs, stripped, uncuddled = self.__uncuddle_augmented_string(substring, augmented)

        # Once the characters cuddling the substring have been removed, update the
        # cache with the transformed string so we can avoid processing it again.
        transformed = self.__cache__[stripped] if stripped in self.__cache__ else ','.join(self.__cache__.get(item, item) for item in self.__process_augmented(uncuddled, stripped, separators=separators))
        #print(['uncuddle', pairs, substring, stripped, transformed])
        self.__cache__[substring] = transformed = pairs[0] + transformed + pairs[-1]
        return transformed

    def process_branch(self, index, substring, separators={','}):
        '''Process the given `substring` at the specified `index` split by the tokens in `separators`.'''
        if self.pairs.get(substring[:1]) != substring[-1:]:
            transformed = self.process_nopair(index, substring, separators=separators)
        else:
            transformed = self.process_pair(index, substring, separators=separators)

        # After processing a branch, update all references to it in the index.
        iterable = (segment for depth, segment in self.__duplicates__.get(index, []))
        [self.__index__.setdefault(left, transformed) for left, right in iterable]
        return transformed

    def __uncuddle_augmented_string(self, string, augmented):
        '''Return a tuple composed of the grouping characters, the ungrouped `string`, and an iterable containing each `augmented` segment.'''
        begin, end = string[:+1], string[-1:]
        if end != self.pairs.get(begin):
            return '', string, (item for item in augmented)

        # otherwise we're safe to shave off the first and last characters.
        elif len(augmented) > 1:
            [(left, index, right)] = augmented[:+1]
            first = max(0, left - 1), index, right
            [(left, index, right)] = augmented[-1:]
            last = left, index, right - 1
            return begin + end, string[+1 : -1], itertools.chain([first], augmented[+1 : -1], [last])

        # if it's a single element, then tweak it a bit.
        elif augmented:
            [(left, index, right)] = augmented
            first, last = max(0, left - 1), max(0, right - 1)
            return begin + end, string[+1 : -1], (item for item in [(first, index, last)])

        # if there's nothing in our augmented list, then just trim the string.
        return begin + end, string[+1 : -1], (item for item in augmented)

    def __repr__(self):
        '''Return a multiple-line description of the attributes belonging to the object.'''
        res, cls, string = [], super(parseable, self).__repr__(), self.__string__

        res.append("length: {:d}".format(len(string)))
        res.append("nested: {:d}".format(len(self.__tree__)))
        res.append('')

        res.append("<unique segments> {:d}".format(len(self.__unique__)))
        token_table = {}
        for index, (left, right) in enumerate(self.__unique__):
            res.append("[{:d}] {:d} reference{:s} : {:d}..{:d} {!r}".format(index, len(self.__duplicates__[left]), '' if len(self.__duplicates__[left]) == 1 else 's', left, right, string[left : right]))
            token_table[string[left : right]] = left
        res.append('')

        res.append("<cached tokens> {:d}/{:d}".format(sum(1 for string, transformed in self.__cache__.items() if string != transformed), len(self.__cache__)))
        for index, string in enumerate(self.__cache__):
            transformed = self.__cache__[string]
            if string == transformed:
                pass

            elif string in token_table and any(left in self.__tree__ for left, right in self.__tree__[token_table[string]]):
                res.append("[{:d}] {!r}".format(index, string))
                res.append("[{:d}] -> {!r}".format(index, transformed))

            else:
                res.append("[{:d}] {!r} -> {!r}".format(index, string, transformed))
            continue
        res.append('')

        return '\n'.join(itertools.chain([cls], res))
