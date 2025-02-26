r"""
Comment module (internal)

This module contains the functionality for encoding and decoding
arbitrary python objects into IDA's comments and is thus a major
component of the way the tag system in this plugin works.

These encoded python objects are constrained in that they must also
double as being human readable in IDA's disassembly view. This then
allows one to essentially store a dictionary within each comment that
can be used to read/write primitive python objects.

Each comment stored at an address is a list of key-value pairs
separated by newlines. Each key represents a tag and so as a comment,
it has the following appearance.

    [key1] value1
    [key2] value2
    ...

If a comment does not follow this format, then it assumed that the
comment's value is a simple unencoded tag and can be accessed via
the '' key (empty). This means that if your comment is simply the
string "HeapHandle", then its dictionary will look similar to
`{'' : 'HeapHandle'}`.

Unfortunately IDA has a limitation on the length of comments and so
arbitrarily long data will not be able to be stored. This includes
things such as more complex types or custom objects. If one truly
needs to store a more complex type then it is suggested that the user
marshal or pickle their object, compress it in some way, and then
base64 encode it at a given address with their key. Still this is not
recommended, but who am I to stop a user from wanting to be crazy.

Some of the values are encoded in order to retain any specific
information about the value as well as still allowing the user to read
the tag's immediate contents. By default all integers are always
encoded as hexadecimal. If you can't read hex, then you should save
your database and quit your job. Or you could also practice it I guess.
It's the next power of 2 from decimal and is hence pretty important.
Strings and other types that contain any line-breaking characters also
get encoded whereas both lists and most iterable types are stored as-is.

Some examples of how tag values are encoded are as follows:

    4021 -> 0xfb5
    -100 -> -0x64
    0.5 -> float(0.5)
    'hello world\nhow\'re ya' -> hello world\nhow're ya
    {10,20,30} -> set([10, 20, 30])

With regards to string, only certain characters are escaped because
I don't know if IDA's comments support unicode. So, the characters
that have special meaning are '\n', '\r', and '\t'. Similarly if a
backslash is escaped, it will result in a single '\'. If any other
character is prefixed with a backslash, it will decode into a character
that is prefixed with a backslash.
"""

import functools, operator, itertools
import collections, heapq, string
import sys, logging

import idaapi, internal, internal.netnode
import codecs

### cheap data structure for doing pattern matching with
class pattern(object):
    class star(tuple): pass
    class maybe(tuple): pass

class node(dict):
    id = 0
    def __missing__(self, token):
        cls = self.__class__

        res = cls()
        res.id = self.id + len(self) + 1
        return self.setdefault(token, res)

class trie(node):
    def assign(self, symbols, value):
        res = [item for item in symbols]
        head = res.pop(0)
        symbols = tuple(res)

        head = head if hasattr(head, '__iter__') or len(head) > 1 else (head,)
        if isinstance(head, pattern.star):
            if len(symbols) <= 0:
                raise ValueError('Refusing to register the STAR(*) pattern as the last symbol')

            [ self.__setitem__(item, self) for item in head ]
            self.assign(symbols, value)
            return

        elif isinstance(head, pattern.maybe):
            if len(symbols) <= 0:
                raise ValueError('Refusing to register the MAYBE(?) pattern as the last symbol')
            head, res = tuple(head), trie()
            res.assign(symbols, value)
            [ self.__setitem__(item, res) for item in head ]
            self.assign(symbols, value)
            return

        elif len(symbols) > 0:
            [ self[item].assign(symbols, value) for item in head ]

        else:
            [ self.__setitem__(item, value) for item in head ]
        return

    def descend(self, symbols):
        yield self
        for i, symbol in enumerate(symbols):
            if not isinstance(self, node) or not operator.contains(self, symbol):
                raise KeyError(i, symbol)    # raise KeyError for .get() and .find()
            self = self[symbol]
            yield self
        return

    def get(self, symbols):
        for i, symbol in enumerate(self.descend(symbols)):
            continue
        if isinstance(symbol, node):
            raise KeyError(i, symbol)    # raise KeyError for our caller if we couldn't find anything
        return symbol

    def find(self, symbols):
        for i, symbol in enumerate(self.descend(symbols)):
            if not isinstance(symbol, node):
                return symbol
            continue
        raise KeyError(i, symbol)    # raise KeyError for our caller if we couldn't find anything

    def dump(self):
        cls = self.__class__
        # FIXME: doesn't support recursion
        def stringify(layer, indent=0, tab='  '):
            result = []

            # iterate through data
            for key, value in layer.items():
                if not isinstance(value, node):
                    result.append("{:s}{!r} -> {!r}".format(tab * indent, key, value))
                continue

            # iterate through branches
            for key, value in layer.items():
                if isinstance(value, node):
                    result.append("{:s}{!r}".format(tab * indent, key))
                    branch_data = stringify(value, 1 + indent, tab=tab)
                    result.extend(branch_data)
                continue
            return result
        return '\n'.join(["{!r}({:d})".format(cls, self.id), '\n'.join(stringify(self))])

### cache for looking up encoder/decoder types
class cache(object):
    state, tree = collections.defaultdict(set), trie()

    @classmethod
    def register(cls, type, *characters):
        def result(definition):
            # add definition to constant search by specified type
            cls.state[type].add(definition)

            # add definition to symbolic search
            if characters:
                cls.tree.assign(characters, definition)

            return definition
        return result

    @classmethod
    def by(cls, instance):
        type = instance.__class__
        try:
            if type not in cls.state:
                type = next(t for t in cls.state if issubclass(type, t))
            res = next(enc for enc in cls.state[type] if enc.type(instance))
        except StopIteration:
            raise internal.exceptions.SerializationError(u"{:s}.by({!s}) : Unable to find an encoder for the serialization of the specified type ({!s}).".format('.'.join([__name__, cls.__name__]), type, type))
        return res

    @classmethod
    def match(cls, string):
        return cls.tree.find(string)

class default(object):
    @classmethod
    def type(cls, instance):
        return True
    @classmethod
    def encode(cls, instance):
        return repr(instance)
    @classmethod
    def decode(cls, data):
        return eval(data)

### type encoder/decoder registration

# FIXME: maybe figure out how to parse out an int from a long in Python2 (which ends in 'L')
@cache.register(object, pattern.star(' \t'), pattern.maybe('-+'), '0123456789')
class _int(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, internal.types.integer)

    @classmethod
    def encode(cls, instance):
        return "{:-#x}".format(instance)

    # Build a table of prefixes and their radix for O(1) lookup.
    radixtable = {}
    for prefix in ['0x', '-0x', '+0x']: radixtable[prefix] = 16
    for prefix in ['0o', '-0o', '+0o']: radixtable[prefix] = 8
    for prefix in ['0b', '-0b', '+0b']: radixtable[prefix] = 2

    # We use a negative radix as a placeholder since Python doesn't know this prefix.
    for prefix in ['0y', '-0y', '+0y']: radixtable[prefix] = -2

    @classmethod
    def decode(cls, data):
        length = 2 if data[0] == '0' else 3
        prefix = data[:length]

        # Grab the radix using our precalculated prefix table. If our radix
        # is positive, then we can just pass it to `int` to get the value.
        radix = cls.radixtable.get(prefix, 0)
        if radix > 0:
            return int(data, radix)

        # If the radix is negative, then we need to explicitly slice off
        # the prefix before passing the radix to our value.
        elif radix < 0:
            return -int(data[length:], abs(radix)) if prefix[:1] == '-' else int(data[length:], abs(radix))

        # Otherwise we couldn't find a radix, and we need to hand it off to
        # `int` to try parsing it as an integer.
        return int(data)

@cache.register(object, pattern.star(' \t'), *'float(')
class _float(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, internal.types.float)
    @classmethod
    def encode(cls, instance):
        return "float({:f})".format(instance)

if sys.version_info.major < 3:
    @cache.register(str)
    class _str(default):
        """
        This encoder/decoder actually supports both ``unicode`` and regular
        ``str`` due to the ``type`` method checking both string types. Also,
        we use this class as a superclass for ``_unicode`` so that any kind
        of string will be encoded into a unicode string which will be
        converted into UTF8 when written into IDA.
        """

        @classmethod
        def type(cls, instance):
            return isinstance(instance, internal.types.string)

        @classmethod
        def _unescape(cls, iterable):
            '''Invert the utils.character.unescape coroutine into a generator.'''
            state = internal.interface.collect_t(list, lambda agg, ch: agg + [ch])
            unescape = internal.utils.character.unescape(state); next(unescape)

            # iterate through each character in the string
            for ch in iterable:
                unescape.send(ch)

                # iterate through the results and yield them to the caller
                for ch in state.get():
                    yield ch

                # now we can start over
                state.reset()
            return

        @classmethod
        def _escape(cls, iterable):
            '''Invert the utils.character.escape coroutine into a generator.'''
            state = internal.interface.collect_t(list, lambda agg, ch: agg + [ch])
            escape = internal.utils.character.escape(state); next(escape)

            # iterate through each character in the string
            for ch in iterable:
                escape.send(ch)

                # iterate through the results and yield them to the caller
                for ch in state.get():
                    yield ch

                # empty our state and start over
                state.reset()
            return

        @classmethod
        def decode(cls, data):
            res = data if isinstance(data, unicode) else data.decode('utf8')
            iterable = (ch for ch in res.lstrip())
            return unicode().join(cls._unescape(iterable))

        @classmethod
        def encode(cls, instance):
            iterable = (item for item in instance)
            res = cls._escape(iterable)
            return unicode().join(res)

    @cache.register(unicode, pattern.star(' \t'), 'u', "'\"")
    class _unicode(_str):
        """
        This encoder/decoder really just a wrapper around the ``_str``
        class. Its encoder will simply escape the string in the exact
        same way as ``_str``. We register a pattern for it so that we
        can decode unicode strings encoded in their older format. Due
        to the older format requiring unicode strings to begin with
        the "u'" prefix, we can simply eval it in order to decode
        back to a unicode string.
        """

        @classmethod
        def type(cls, instance):
            return isinstance(instance, unicode)

        @classmethod
        def decode(cls, data):
            logging.warning(u"{:s}.decode({!s}) : Decoding a unicode string that was encoded using the old format.".format('.'.join([__name__, cls.__name__]), internal.utils.string.repr(data)))
            return eval(data)

else:
    @cache.register(bytes, pattern.star(' \t'), 'b', "'\"")
    class _bytes(default):
        @classmethod
        def type(cls, instance):
            return isinstance(instance, internal.types.bytes)

        @classmethod
        def decode(cls, data):
            return eval(data)

        @classmethod
        def encode(cls, instance):
            return repr(instance)

    @cache.register(str)
    class _str(default):
        @classmethod
        def type(cls, instance):
            return isinstance(instance, internal.types.string)

        @classmethod
        def _unescape(cls, iterable):
            '''Invert the utils.character.unescape coroutine into a generator.'''
            state = internal.interface.collect_t(list, lambda agg, ch: agg + [ch])
            unescape = internal.utils.character.unescape(state); next(unescape)

            # iterate through each character in the string
            for ch in iterable:
                unescape.send(ch)

                # iterate through the results and yield them to the caller
                for ch in state.get():
                    yield ch

                # now we can start over
                state.reset()
            return

        @classmethod
        def _escape(cls, iterable):
            '''Invert the utils.character.escape coroutine into a generator.'''
            state = internal.interface.collect_t(list, lambda agg, ch: agg + [ch])
            escape = internal.utils.character.escape(state); next(escape)

            # iterate through each character in the string
            for ch in iterable:
                escape.send(ch)

                # iterate through the results and yield them to the caller
                for ch in state.get():
                    yield ch

                # empty our state and start over
                state.reset()
            return

        @classmethod
        def decode(cls, data):
            res = data if isinstance(data, internal.types.string) else data.decode('utf8')
            return str().join(cls._unescape(iter(res.lstrip())))

        @classmethod
        def encode(cls, instance):
            res = cls._escape(iter(instance))
            return str().join(res)

@cache.register(dict, pattern.star(' \t'), '{')
class _dict(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, internal.types.dictionary)
    @classmethod
    def encode(cls, instance):
        f = lambda item: "{:-#x}".format(item) if isinstance(item, internal.types.integer) else "{!r}".format(item)
        return '{' + ', '.join("{:s}: {!r}".format(f(key), instance[key]) for key in instance) + '}'

@cache.register(list, pattern.star(' \t'), '[')
class _list(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, internal.types.list)
    @classmethod
    def encode(cls, instance):
        f = lambda item: "{:-#x}".format(item) if isinstance(item, internal.types.integer) else "{!r}".format(item)
        return '[' + ', '.join(map(f, instance)) + ']'

@cache.register(tuple, pattern.star(' \t'), '(')
@cache.register(object, pattern.star(' \t'), '(')
class _tuple(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, internal.types.tuple)
    @classmethod
    def encode(cls, instance):
        f = lambda item: "{:-#x}".format(item) if isinstance(item, internal.types.integer) else "{!r}".format(item)
        return '(' + ', '.join(map(f, instance)) + (', ' if len(instance) == 1 else '') + ')'

@cache.register(set, pattern.star(' \t'), *'set([')
class _set(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, internal.types.set)
    @classmethod
    def encode(cls, instance):
        f = lambda item: "{:-#x}".format(item) if isinstance(item, internal.types.integer) else "{!r}".format(item)
        return 'set([' + ', '.join(map(f, instance)) + '])'

### general tag encoding/decoding
class tag(object):
    """
    Namespace for encoding and decoding a tag and it's value.
    """

    ## Tag name
    class name(object):
        """
        Namespace for encoding and decoding a tag's name.
        """

        prefix, suffix = '[]'
        backslash = '\\'

        mappings = {
            prefix : backslash + prefix,
            suffix : backslash + suffix,
            ' ' : r' ',
            backslash : backslash + backslash,
        }

        @classmethod
        def encode(cls, iterable, result):
            '''Given an `iterable` string, send each character in a printable form to `result`.'''

            # construct a transformer that writes characters to result
            escape = internal.utils.character.escape(result); next(escape)

            # send the key prefix
            result.send(cls.prefix)

            # now we can actually process the string
            for ch in iterable:

                # first check if character has an existing key mapping
                if operator.contains(cls.mappings, ch):
                    for ch in operator.getitem(cls.mappings, ch):
                        result.send(ch)

                # otherwise pass it to the regular escape function
                else:
                    escape.send(ch)

                continue

            # submit the suffix and we're good
            result.send(cls.suffix)
            return

        @classmethod
        def decode(cls, iterable, result):
            '''Given an `iterable`, decode it into a unicode string and send it to `result`.'''

            # first create our aggregate type for decoding into
            agg = internal.interface.collect_t(unicode if sys.version_info.major < 3 else str, operator.add)

            # construct a transformer that unescapes characters to result
            unescape = internal.utils.character.unescape(agg); next(unescape)

            # first we'll skip the initial whitespace
            ch = next(iterable)
            while ch != cls.prefix and internal.utils.character.whitespaceQ(ch):
                ch = next(iterable)

            # check if it matches our prefix (which it should)
            if ch != cls.prefix:
                raise internal.exceptions.InvalidFormatError(u"{:s}.decode({!s}, {!s}) : Input for tag name does not begin with the proper character ('{:s}') and instead starts with '{:s}'.".format('.'.join([__name__, 'tag', cls.__name__]), iterable, result, internal.utils.string.escape(cls.prefix, '\''), internal.utils.string.escape(ch, '\'')))

            # read each character up to the sentinel
            agg.reset()
            ch = next(iterable)

            # loop until we find our suffix
            while ch != cls.suffix:

                # submit our character to the unescape transformer while
                # it's a backslash
                while ch in u'\\':
                    unescape.send(ch)
                    ch = next(iterable)

                # otherwise, continue to unescape it and look for a suffix
                unescape.send(ch)
                ch = next(iterable)

            # the last character read should be our suffix, so fail if otherwise
            if ch != cls.suffix:
                raise internal.exceptions.InvalidFormatError(u"{:s}.decode({!s}, {!s}) : Input for tag name does not terminate with the correct character ('{:s}') and instead is terminated with '{:s}'.".format('.'.join([__name__, 'tag', cls.__name__]), iterable, result, internal.utils.string.escape(cls.suffix, '\''), internal.utils.string.escape(ch, '\'')))

            # at this point, agg should have our unescaped key that we can submit
            result.send(agg.get())

    ## Tag value
    class value(object):
        """
        Namespace for encoding and decoding a tag's value.
        """

        @classmethod
        def encode(cls, iterable, result):
            '''Read a value from `iterable` and encode it into `result`.'''
            value = next(iterable)
            t = cache.by(value)
            for ch in t.encode(value):
                result.send(ch)
            return

        @classmethod
        def decode(cls, iterable, result):
            '''Given an `iterable`, decode it into a unicode string and send it to `result`.'''
            res = []

            # first we'll skip whitespace
            ch = next(iterable, '\n')
            while ch != '\n' and internal.utils.character.whitespaceQ(ch):
                res.append(ch)
                ch = next(iterable, '\n')

            # if we were just whitespace, then decode it as
            # a unicode string to return
            if ch == '\n':
                cons = unicode if sys.version_info.major < 3 else str
                value_s = cons().join(res)
                result.send(_str.decode(value_s))
                return

            # now we'll continue reading until the sentinel character
            value_l = []
            while ch != '\n':
                value_l.append(ch)
                ch = next(iterable, '\n')
            value_s = str().join(value_l)

            # now we'll try to find out what type to decode it as
            try:
                t = cache.match(value_s)

            except KeyError:
                t = _str

            # we have a type and a value. try to decode it
            try:
                value = t.decode(value_s)

            # if we weren't able to, then fall back to a string
            except Exception as E:
                t = _str
                logging.debug(u"{:s}.decode({!s}, {!s}) : Assuming value ({!s}) is of type {!s}.".format('.'.join([__name__, 'tag', cls.__name__]), iterable, result, internal.utils.string.repr(value_s), t))
                value = t.decode(value_s)

            # now we can submit it
            result.send(value)

    @classmethod
    def encode(cls, key, value):
        '''Encode the provided `key` and `value` into a line fit for a comment.'''
        result = internal.interface.collect_t(unicode if sys.version_info.major < 3 else str, operator.add)

        # first encode the beginning of the name
        tag.name.encode(iter(key), result)

        # store some whitespace in between
        result.send(' ')

        # next encode the value component
        tag.value.encode(iter([value]), result)

        # now we can return the resulting string
        return result.get()

    @classmethod
    def decode(cls, iterable):
        '''Read the line in `iterable` and return the key and its value.'''

        # first decode the key
        key = internal.interface.collect_t(object, lambda agg, key: key)
        tag.name.decode(iterable, key)

        # next decode its value
        value = internal.interface.collect_t(object, lambda agg, value: value)
        tag.value.decode(iterable, value)

        # plain and simple...
        return key.get(), value.get()

### Encoding and decoding of a comment
def decode(data, default=u''):
    """Decode all the `(key, value)` pairs from the string `data` delimited by newlines.

    If unable to decode the key and value from a line in `data`, then use `default` as the key name.
    """

    # if data is empty, then return an empty dict
    if not data:
        return {}

    # iterate through each line in the data so that we can collect it
    # into our result dictionary.
    result = {}
    for line in data.split(u'\n'):
        iterable = (ch for ch in line)

        # try and decode the key and the value from the line
        try:
            key, value = tag.decode(iterable)

        # if the key wasn't terminated properly or the line was not
        # formatted correctly, then fall back to using the default key.we
        # first need to grab the value of the default key from our result
        # dictionary because we need to ensure it's a string so that we
        # can actually append our corrupted value to it.
        except (StopIteration, internal.exceptions.InvalidFormatError) as E:
            key, value = default, result.setdefault(default, u'')

            # if our previous value is already a string, then we can use
            # it as-is and append it to the default key separated by a newline.
            if isinstance(value, internal.types.string):
                string = value

            # if it's not, however, then we need to demote the value to
            # a string by temporarily encoding it. this is hackish, but
            # its okay because we're warning the user about it anywayz.
            else:
                logging.warning(u"{:s}.decode(..., {!s}) : Coercing the prior value ({!s}) for the decoded tag ({!s}) to a {!s} due to its value being of a non-cumulative type ({!s}).".format('.'.join([__name__]), internal.utils.string.repr(key), internal.utils.string.repr(value), internal.utils.string.repr(key), key.__class__, value.__class__))

                # now we can collect it into a string...
                collected_value = internal.interface.collect_t(unicode if sys.version_info.major < 3 else str, operator.add)
                tag.value.encode(iter([value]), collected_value)
                string = collected_value.get()

            # now we should have a proper string that we can append our
            # incorrectly formatted tag and value to.
            items = filter(None, string.split(u'\n'))
            value = u'\n'.join(itertools.chain(items, [line]))

        # if there was no exception, but the key that we decoded can potentially
        # overwrite an already existing key in our result dictionary, then we will
        # still need to warn the user about it because we're being destructive.
        # NOTE: another option here to avoid being destructive is to demote the
        #       previous dictionary value to a string, and append to it. personally
        #       i believe that warning the user should be enough so that way we don't
        #       interfere with any scripting that they might currently be performing.
        else:
            if operator.contains(result, key):
                logging.warning(u"{:s}.decode(..., {!s}) : Overwriting the value ({!r}) for the decoded tag ({!s}) using a new value ({!r}) of {!s}.".format('.'.join([__name__]), internal.utils.string.repr(default), result[key], internal.utils.string.repr(key), value, value.__class__))

        # add our item to the result dictionary
        result[key] = value

    # return the dictionary we decoded
    return result

def encode(dict):
    '''Encode a dictionary into a multi-line string encoded as a list of tags.'''
    result = []

    # walk each item in the dictionary, so that we can encode
    # each key and value into a single line and aggregate them
    # into our result list.
    for key, value in (dict or {}).items():
        line = tag.encode(key, value)
        result.append(line)

    # now we can join them with newlines and return it to the caller
    return '\n'.join(result)

def check(data):
    '''Check that the string `data` has the correct format by trying to decode it.'''
    res = map(iter, (data or '').split('\n'))
    try:
        [tag.decode(item) for item in res]
    except Exception as E:
        return False
    return True

### Define some namespaces that can be used to interact with "extra" comments.

class extra_pre70(object):
    """
    This namespace is a base class for interacting with the "extra" comments
    that are within the database. Specifically, the implemented functionality
    is used to interact with versions of the disassembler prior to v7.0. The
    class itself is intended to be inherited from by a frontend class once
    the disassembler version is known.
    """

    @classmethod
    def hide(cls, ea):
        '''Hide the extra comments at the address `ea`.'''
        ok = internal.interface.address.flags(int(ea), idaapi.FF_LINE) == idaapi.FF_LINE
        if ok:
            discarded = internal.interface.address.flags(int(ea), idaapi.FF_LINE, 0)
        return True if ok else False

    @classmethod
    def show(cls, ea):
        '''Show the extra comments at the address `ea`.'''
        ok = internal.interface.address.flags(int(ea), idaapi.FF_LINE) != idaapi.FF_LINE
        if ok:
            discarded = internal.interface.address.flags(int(ea), idaapi.FF_LINE, idaapi.FF_LINE)    # FIXME: IDA 7.0 : ida_nalt.set_visible_item?
        return True if ok else False

    @classmethod
    def get(cls, ea, base):
        '''Fetch the extra comments from the address `ea` that are specified by the index in `base`.'''
        ea, sup, Fnetnode = int(ea), internal.netnode.sup, getattr(idaapi, 'ea2node', internal.utils.fidentity)

        # count the number of rows
        count = cls.count(ea, base)
        if count is None: return None

        # now we can fetch them
        res = (sup.get(Fnetnode(ea), base + i, type=internal.types.bytes) for i in range(count))

        # remove the null-terminator if there is one
        res = (row.rstrip(b'\0') for row in res)

        # fetch them from IDA and join them with newlines
        return '\n'.join(map(internal.utils.string.of, res))

    @classmethod
    def set(cls, ea, string, base):
        '''Set the newline-delimited `string` as the extra comments for the address `ea` at the index specified by `base`.'''
        ea, sup, Fnetnode = int(ea), internal.netnode.sup, getattr(idaapi, 'ea2node', internal.utils.fidentity)

        # first hide the extra comment before doing anything
        discarded, string = cls.hide(ea), internal.utils.string.of(string)

        # break the string up into rows, and encode each type for IDA
        res = [ internal.utils.string.to(item) for item in string.split('\n') ]

        # assign them directly into IDA
        [ sup.set(Fnetnode(ea), base + i, row + b'\0') for i, row in enumerate(res) ]

        # now we can show (refresh) them
        discarded = cls.show(ea)

        # an exception before this happens would imply failure
        return True

    @classmethod
    def delete(cls, ea, base):
        '''Remove the extra comments from the address `ea` that start at the index in `base`.'''
        ea, sup, Fnetnode = int(ea), internal.netnode.sup, getattr(idaapi, 'ea2node', internal.utils.fidentity)

        # count the number of rows to remove
        count = cls.count(ea, base)
        if count is None:
            return False

        # hide them before we modify it
        discarded = cls.hide(ea)

        # now we can remove them
        [ sup.remove(Fnetnode(ea), base + i) for i in range(count) ]

        # and then show (refresh) it
        discarded = cls.show(ea)
        return True

class extra_post70(object):
    """
    This namespace is a base class for interacting with the "extra" comments
    that may be found within a database. The functionality implemented by
    this namespace is used to interact with newer versions of the disassembler.
    Specifically, this class supports v7.0 of the disassembler and newer. The
    class is intended to be inherited from by a frontend once the disassembler
    version has been determined.
    """
    @classmethod
    def get(cls, ea, base):
        '''Fetch the extra comments from the address `ea` that are specified by the index in `base`.'''
        ea = int(ea)

        # count the number of rows
        count = cls.count(ea, base)
        if count is None:
            return None

        # grab the extra comments from the database
        iterable = (idaapi.get_extra_cmt(ea, base + i) or '' for i in range(count))

        # convert them back into Python and join them with a newline
        iterable = (internal.utils.string.of(item) for item in iterable)
        return '\n'.join(iterable)

    @classmethod
    def set(cls, ea, string, base):
        '''Set the newline-delimited `string` as the extra comments for the address `ea` at the index specified by `base`.'''
        ea, string = int(ea), internal.utils.string.of(string)

        # break the string up into rows, and encode each type for IDA
        iterable = (internal.utils.string.to(item) for item in string.split('\n'))

        # assign them into IDA using its api
        [ idaapi.update_extra_cmt(ea, base + i, row) for i, row in enumerate(iterable) ]

        # return how many newlines there were
        return string.count('\n')

    @classmethod
    def delete(cls, ea, base):
        '''Remove the extra comments from the address `ea` that start at the index in `base`.'''
        ea = int(ea)

        # count the number of extra comments to remove
        res = cls.count(ea, base)
        if res is None:
            return 0

        # now we can delete them using the api
        [idaapi.del_extra_cmt(ea, base + i) for i in range(res)]

        # return how many comments we deleted
        return res

## Now we can define the namespace intended for dealing with extra comments.

class extra(extra_pre70 if idaapi.__version__ < 7.0 else extra_post70):
    """
    This namespace is used for reading the disassemblers "extra" comments
    from the database in a way that is portable between the different versions
    of the disassembler. These "extra" comments are also known "anterior" and
    "posterior" lines. Most of the core functionality within this namespace
    uses the methods inherited from its base class in order to remain
    backwards-compatible with older versions of the disassembler.
    """

    MAX_ITEM_LINES = 5000   # defined in cfg/ida.cfg according to python/idc.py
    MAX_ITEM_LINES = (idaapi.E_NEXT - idaapi.E_PREV) if idaapi.E_NEXT > idaapi.E_PREV else (idaapi.E_PREV - idaapi.E_NEXT)

    @classmethod
    def has_extra(cls, ea, base):
        '''Return true if there is an extra comment at the supval `base` for the address `ea`.'''
        ea, sup, Fnetnode = int(ea), internal.netnode.sup, getattr(idaapi, 'ea2node', internal.utils.fidentity)
        return sup.get(Fnetnode(ea), base, type=memoryview) is not None

    @classmethod
    def count(cls, ea, base):
        '''Return the number of extra comments for the address `ea` that start at the supval `base`.'''
        ea, sup, Fnetnode = int(ea), internal.netnode.sup, getattr(idaapi, 'ea2node', internal.utils.fidentity)
        for i in range(cls.MAX_ITEM_LINES):
            row = sup.get(Fnetnode(ea), base + i, type=memoryview)
            if row is None: break
        return i or None

    @classmethod
    def has_prefix(cls, ea):
        '''Return true if there are any extra comments that prefix the item at the address `ea`.'''
        return cls.has_extra(int(ea), idaapi.E_PREV)

    @classmethod
    def has_suffix(cls, ea):
        '''Return true if there are any extra comments that suffix the item at the address `ea`.'''
        return cls.has_extra(int(ea), idaapi.E_NEXT)

    ### The following methods are actually used to get or set the extra comments at an address.

    @classmethod
    def get_prefix(cls, ea):
        '''Return the prefixed comment at address `ea`.'''
        return cls.get(int(ea), idaapi.E_PREV)

    @classmethod
    def get_suffix(cls, ea):
        '''Return the suffixed comment at address `ea`.'''
        return cls.get(int(ea), idaapi.E_NEXT)

    @classmethod
    def delete_prefix(cls, ea):
        '''Delete the prefixed comment at address `ea`.'''
        res = cls.get(int(ea), idaapi.E_PREV)
        count = cls.delete(int(ea), idaapi.E_PREV)
        return res

    @classmethod
    def delete_suffix(cls, ea):
        '''Delete the suffixed comment at address `ea`.'''
        res = cls.get(int(ea), idaapi.E_NEXT)
        count = cls.delete(int(ea), idaapi.E_NEXT)
        return res

    @classmethod
    def set_prefix(cls, ea, string):
        '''Set the prefixed comment at address `ea` to the specified `string`.'''
        ea = int(ea)
        res, ok = cls.delete_prefix(ea), cls.set(ea, string, idaapi.E_PREV)
        ok = cls.set(ea, string, idaapi.E_PREV)
        return res

    @classmethod
    def set_suffix(cls, ea, string):
        '''Set the suffixed comment at address `ea` to the specified `string`.'''
        ea = int(ea)
        res, ok = cls.delete_suffix(ea), cls.set(ea, string, idaapi.E_NEXT)
        return res

    ### These private methods are used to explicitly set the whitespace (newlines)
    ### for an extra comment using a numberical count instead of a string.

    @classmethod
    def __insert_whitespace(cls, ea, count, getter, setter, remover):
        '''Use the callables specified by `getter`, `setter`, and `remover` to insert `count` lines of whitespace in front of the extra comment for address `ea`.'''
        ea = int(ea)

        # Start by getting the current contents of the desired extra comment.
        res = getter(ea)

        # Then we strip out any newlines in front of it, and then either assign
        # some new ones or remove the old ones depending on the chosen count.
        lstripped, nl = ('', 0) if res is None else (res.lstrip('\n'), len(res) - len(res.lstrip('\n')) + 1)
        return setter(ea, '\n' * (nl + count - 1) + lstripped) if nl + count > 0 or lstripped else remover(ea)

    @classmethod
    def __append_whitespace(cls, ea, count, getter, setter, remover):
        '''Use the callables specified by `getter`, `setter`, and `remover` to append `count` lines of whitespace after the extra comment for address `ea`.'''
        ea = int(ea)

        # First we need to get the contents of the extra comment they wanted.
        res = getter(ea)

        # Next we strip out any trailing newlines, and then assign the new
        # ones or remove the old ones depending on the specified count.
        rstripped, nl = ('', 0) if res is None else (res.rstrip('\n'), len(res) - len(res.rstrip('\n')) + 1)
        return setter(ea, rstripped + '\n' * (nl + count - 1)) if nl + count > 0 or rstripped else remover(ea)

    ### Now we define some utility functions that are intended to be used as the
    ### frontend to explicitly control the newlines used by an extra comment.

    @classmethod
    def insert_anterior(cls, ea, count):
        '''Insert `count` lines in front of the anterior comment for the item at address `ea`.'''
        res = cls.get_prefix, cls.set_prefix, cls.delete_prefix
        return cls.__insert_whitespace(ea, count, *res)

    @classmethod
    def append_anterior(cls, ea, count):
        '''Append `count` lines after the anterior comment for the item at address `ea`.'''
        res = cls.get_prefix, cls.set_prefix, cls.delete_prefix
        return cls.__append_whitespace(ea, count, *res)

    @classmethod
    def insert_posterior(cls, ea, count):
        '''Insert `count` lines in front of the posterior comment for the item at address `ea`.'''
        res = cls.get_suffix, cls.set_suffix, cls.delete_suffix
        return cls.__insert_whitespace(ea, count, *res)

    @classmethod
    def append_posterior(cls, ea, count):
        '''Append `count` lines after the posterior comment for the item at address `ea`.'''
        res = cls.get_suffix, cls.set_suffix, cls.delete_suffix
        return cls.__append_whitespace(ea, count, *res)
