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

import itertools, functools, operator
import collections, heapq, string
import six, logging

import internal, idaapi
import codecs

class trie(dict):
    class star(tuple): pass
    class maybe(tuple): pass

    id = 0
    def __missing__(self, token):
        res = trie()
        res.id = self.id + len(self) + 1
        return self.setdefault(token, res)

    def assign(self, symbols, value):
        head = symbols[0]
        head = head if hasattr(head, '__iter__') or len(head) > 1 else (head,)
        if len(symbols) > 1:
            if isinstance(head, trie.star):
                [ self.__setitem__(n, self) for n in head ]
                self.assign(symbols[1:], value)
                return
            elif isinstance(head, trie.maybe):
                head, res = tuple(head), trie()
                res.assign(symbols[1:], value)
                [ self.__setitem__(n, res) for n in head ]
                self.assign(symbols[1:], value)
                return
            [ self[n].assign(symbols[1:], value) for n in head ]
            return
        [ self.__setitem__(n, value) for n in head ]
        return

    def descend(self, symbols):
        yield self
        for i, n in enumerate(symbols):
            if not isinstance(self, trie) or (n not in self):
                raise KeyError(i, n)    # raise KeyError for .get() and .find()
            self = self[n]
            yield self
        return

    def get(self, symbols):
        for i, n in enumerate(self.descend(symbols)):
            continue
        if isinstance(n, trie):
            raise KeyError(i, n)    # raise KeyError for our caller if we couldn't find anything
        return n

    def find(self, symbols):
        for i, n in enumerate(self.descend(symbols)):
            if not isinstance(n, trie):
                return n
            continue
        raise KeyError(i, n)    # raise KeyError for our caller if we couldn't find anything

    def dump(self):
        cls = self.__class__
        # FIXME: doesn't support recursion
        def stringify(node, indent=0, tab='  '):
            data = (k for k, v in node.viewitems() if not isinstance(v, trie))
            result = []
            for k in data:
                result.append("{:s}{!r} -> {!r}".format(tab * indent, k, node[k]))

            branches = [k for k, v in node.viewitems() if isinstance(v, trie)]
            for k in branches:
                result.append("{:s}{!r}".format(tab * indent, k))
                branch_data = stringify(node[k], indent+1, tab=tab)
                result.extend(branch_data)
            return result
        return '\n'.join(("{!r}({:d})".format(cls, self.id), '\n'.join(stringify(self))))

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
            raise internal.exceptions.SerializationError(u"{:s}.by({!s}) : Unable to find an encoder for the serialization of the specified type ({!s}).".format('.'.join(('internal', __name__, cls.__name__)), type, type))
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

# FIXME: maybe figure out how to parse out an int from a long (which ends in 'L')
@cache.register(object, trie.star(' \t'), trie.maybe('-+'), '0123456789')
class _int(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, six.integer_types)
    @classmethod
    def encode(cls, instance):
        return "{:-#x}".format(instance)

@cache.register(object, trie.star(' \t'), *'float(')
class _float(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, float)
    @classmethod
    def encode(cls, instance):
        return "float({:f})".format(instance)

@cache.register(str)
class _str(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, str)

    uncmap = { ch : six.int2byte(i) for i, ch in enumerate('0123456abtnvfr') }
    @classmethod
    def _unescape(cls, iterable):
        try:
            while True:
                ch = next(iterable)
                if ch == '\\':
                    ch = next(iterable)
                    # double-backslash reduced down to a single one
                    if ch == '\\':
                        yield '\\'
                    # standard escaped character
                    elif ch in cls.uncmap:
                        yield cls.uncmap[ch]
                    # FIXME: read octal digits
                    elif ch in string.digits:
                        pass
                    # FIXME: read hexadecimal digits
                    elif ch in 'x':
                        pass
                    # otherwise it's mistakenly escaped, and python returns both
                    else:
                        yield '\\';
                        yield ch
                    continue
                yield ch
        except StopIteration: pass

    cmap = { six.int2byte(i) : ch for i, ch in enumerate('0123456abtnvfr') }
    @classmethod
    def _escape(cls, iterable):
        try:
            while True:
                ch = next(iterable)
                # if it's a single backslash, then double it.
                if ch == '\\':
                    yield '\\'
                    yield '\\'
                # if it's a known escapable character, then return it
                elif ch in cls.cmap:
                    yield '\\'
                    yield cls.cmap[ch]
                # otherwise, it should be printable and doesn't need to be escaped
                elif ch in string.printable:
                    yield ch
                # we don't know, so let python handle it
                else:
                    # FIXME: replace this repr() hack with a proper \x encoding
                    yield repr(ch)[1:-1]
        except StopIteration: pass

    @classmethod
    def decode(cls, data):
        res = str(data).lstrip()
        return str().join(cls._unescape(iter(res)))
    @classmethod
    def encode(cls, instance):
        res = cls._escape(iter(instance))
        return str().join(res)

@cache.register(unicode, trie.star(' \t'), *"u'")
class _unicode(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, unicode)

@cache.register(dict, trie.star(' \t'), '{')
class _dict(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, dict)
    @classmethod
    def encode(cls, instance):
        f = lambda item: "{:-#x}".format(item) if isinstance(item, six.integer_types) else "{!r}".format(item)
        return '{' + ', '.join("{:s} : {!r}".format(f(key), instance[key]) for key in instance) + '}'

@cache.register(list, trie.star(' \t'), '[')
class _list(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, list)
    @classmethod
    def encode(cls, instance):
        f = lambda n: "{:-#x}".format(n) if isinstance(n, six.integer_types) else "{!r}".format(n)
        return '[' + ', '.join(map(f, instance)) + ']'

@cache.register(tuple, trie.star(' \t'), '(')
class _tuple(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, tuple)
    @classmethod
    def encode(cls, instance):
        f = lambda n: "{:-#x}".format(n) if isinstance(n, six.integer_types) else "{!r}".format(n)
        return '(' + ', '.join(map(f, instance)) + (', ' if len(instance) == 1 else '') + ')'

@cache.register(set, trie.star(' \t'), *'set([')
class _set(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, set)
    @classmethod
    def encode(cls, instance):
        f = lambda n: "{:-#x}".format(n) if isinstance(n, six.integer_types) else "{!r}".format(n)
        return 'set([' + ', '.join(map(f, instance)) + '])'

### parsing functions
def key_escape(iterable, sentinel):
    try:
        while True:
            ch = next(iterable)
            if ch == '\\':
                ch = next(iterable)
                if   ch == 'n': yield '\n'; continue
                elif ch == 'r': yield '\r'; continue
                elif ch == 't': yield '\t'; continue
            elif ch == sentinel:
                return
            yield ch
    except StopIteration: pass
    raise internal.exceptions.InvalidFormatError(u"{:s}.key_escape({!s}, '{:s}') : Input is not properly terminated with the correct sentinel '{:s}'.".format('.'.join(('internal', __name__)), iterable, internal.utils.string.escape(sentinel, '\''), internal.utils.string.escape(sentinel, '\'')))

def parse_line(iterable):
    ch = next(iterable)
    if ch != '[':
        raise internal.exceptions.InvalidFormatError(u"{:s}.parse_line({!s}) : Input does not begin with the proper character '{:s}' and instead starts with '{:s}'.".format('.'.join(('internal', __name__)), iterable, internal.utils.string.escape('[', '\''), internal.utils.string.escape(ch, '\'')))
    res = key_escape(iterable, ']')
    key = ''.join(res)

    value = ''.join(iterable)
    try:
        t = cache.match(value)
    except KeyError:
        return key, _str.decode(value)

    try:
        res = t.decode(value)
    except:
        t = _str
        logging.debug(u"{:s}.parse_line({!s}) : Assuming tag \"{:s}\" is of type {!s} with the value {!r}.".format('.'.join(('internal', __name__)), iterable, internal.utils.string.escape(key, '"'), t, value))
        res = t.decode(value)
        #raise internal.exceptions.SerializationError(u"Unable to decode data with {!r} : {!r}".format(t, value))
    return key, res

def emit_line(key, value):
    escape = {
        '\\' : r'\\',
        '['  : r'\[',
        ']'  : r'\]',
        '\0' : r'\0',
        '\1' : r'\1',
        '\2' : r'\2',
        '\3' : r'\3',
        '\4' : r'\4',
        '\5' : r'\5',
        '\6' : r'\6',
        '\a' : r'\a',
        '\b' : r'\b',
        '\t' : r'\t',
        '\n' : r'\n',
        '\v' : r'\v',
        '\f' : r'\f',
        '\r' : r'\r',
    }
    # FIXME: should probably use _str.encode here
    k = str().join(escape.get(n, n) for n in key)
    t = cache.by(value)
    return "[{:s}] {:s}".format(k, t.encode(value))

### Encoding and decoding of a comment
def decode(data, default=''):
    """Decode all the `(key, value)` pairs from the string `data` delimited by newlines.

    If unable to decode the key and value from a line in `data`, then use `default` as the key name.
    """
    res = {}
    try:
        for line in (data or '').split('\n'):
            try: k, v = parse_line(iter(line))
            except KeyError: k, v = default, line
            res[k] = v
    except StopIteration: pass
    return res

def encode(dict):
    res = []
    for k, v in six.iteritems(dict or {}):
        res.append(emit_line(k, v))
    return '\n'.join(res)

def check(data):
    res = map(iter, (data or '').split('\n'))
    try:
        map(parse_line, res)
    except (KeyError, StopIteration):
        return False
    return True

### Tag reference counting
class tagging(object):
    __node__ = '$ tagcache'
    __tags__, __address__ = 'name', 'address'

    marshaller = __import__('marshal')
    codec = __import__('codecs').lookup('bz2_codec')

    @classmethod
    def __init_tagcache__(cls, idp_modname):
        cls.node()
        logging.debug(u"{:s}.init_tagcache('{:s}') : Initialized tagcache with netnode \"{:s}\" and node id {:#x}.".format('.'.join(('internal', __name__, cls.__name__)), internal.utils.string.escape(idp_modname, '\''), internal.utils.string.escape(cls.__node__, '"'), cls.__nodeid__))

    @classmethod
    def node(cls):
        if hasattr(cls, '__nodeid__'):
            return cls.__nodeid__
        node = internal.netnode.get(cls.__node__)
        if node == idaapi.BADADDR:
            node = internal.netnode.new(cls.__node__)
        cls.__nodeid__ = node
        return node

class contents(tagging):
    '''Tagging for an address within a function (contents)'''

    ## for each function's content
    # netnode.blob[fn.startEA, btag] = marshal.dumps({'name', 'address'})
    # netnode.sup[fn.startEA] = marshal.dumps({tagnames})

    #btag = idaapi.stag         # XXX: apparently 'S' is used for comments
    btag = idaapi.atag

    @classmethod
    def _key(cls, ea):
        '''Converts address to a key that's used to store arbitrary data'''
        res = idaapi.get_func(ea)
        return res.startEA if res else None

    @classmethod
    def _read_header(cls, target, ea):
        node, key = tagging.node(), cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._read_header({!r}, {:#x}) : Unable to find a function for target ({!r}) at {:#x}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, key, ea))

        encdata = internal.netnode.sup.get(node, key)
        if encdata is None:
            return None

        try:
            data, sz = cls.codec.decode(encdata)
            if len(encdata) != sz:
                raise internal.exceptions.SizeMismatchError(u"{:s}._read_header({!r}, {:#x}) : The number of bytes that was decoded ({:#x}) did not match the expected size ({:+#x}).".format('.'.join(('internal', __name__, cls.__name__)), target, ea, sz, len(encdata)))
        except:
            raise internal.exceptions.SerializationError(u"{:s}._read_header({!r}, {:#x}) : Unable to decode contents for {:#x} at {:#x}. The data that failed to be decoded is {!r}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, key, ea, encdata))

        try:
            result = cls.marshaller.loads(data)
        except:
            raise internal.exceptions.SerializationError(u"{:s}._read_header({!r}, {:#x}) : Unable to unmarshal contents for {:#x} at {:#x}. The data that failed to be unmarshalled is {!r}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, key, ea, data))
        return result

    @classmethod
    def _write_header(cls, target, ea, value):
        node, key = tagging.node(), cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._write_header({!r}, {:#x}, {!s}) : Unable to find a function for target ({!r}) at {:#x}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, internal.utils.string.repr(value), key, ea))

        if not value:
            ok = internal.netnode.sup.remove(node, key)
            return bool(ok)

        try:
            data = cls.marshaller.dumps(value)
        except:
            raise internal.exceptions.SerializationError(u"{:s}._write_header({!r}, {:#x}, {!s}) : Unable to marshal contents for {:#x} at {:#x}. The data that failed to be marshalled is {!r}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, internal.utils.string.repr(value), key, ea, value))

        try:
            encdata, sz = cls.codec.encode(data)
            if sz != len(data):
                raise internal.exceptions.SizeMismatchError(u"{:s}._write_header({!r}, {:#x}, {!s}) : The number of bytes that was encoded ({:#x}) did not match the expected size ({:+#x}).".format('.'.join(('internal', __name__, cls.__name__)), target, ea, internal.utils.string.repr(value), sz, len(data)))
        except:
            raise internal.exceptions.SerializationError(u"{:s}._write_header({!r}, {:#x}, {!s}) : Unable to encode contents for {:#x} at {:#x}. The data that failed to be encoded is {!r}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, internal.utils.string.repr(value), key, ea, data))

        if len(encdata) > internal.netnode.sup.MAX_SIZE:
            logging.warn(u"{:s}._write_header({!r}, {:#x}, {!s}) : Too many tags within function. The size {:#x} must be < {:#x}. Ignoring it.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, internal.utils.string.repr(value), len(encdata), internal.netnode.sup.MAX_SIZE))

        ok = internal.netnode.sup.set(node, key, encdata)
        return bool(ok)

    @classmethod
    def _read(cls, target, ea):
        '''Reads a dictionary from the specific object'''
        node, key = tagging.node(), cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._read({!r}, {:#x}) : Unable to find a function for target ({!r}) at {:#x}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, key, ea))

        encdata = internal.netnode.blob.get(key, cls.btag)
        if encdata is None:
            return None

        try:
            data, sz = cls.codec.decode(encdata)
            if len(encdata) != sz:
                raise internal.exceptions.SizeMismatchError(u"{:s}._read({!r}, {:#x}) : The number of bytes that was decoded ({:#x}) did not match the expected size ({:+#x}).".format('.'.join(('internal', __name__, cls.__name__)), target, ea, sz, len(encdata)))
        except:
            raise internal.exceptions.SerializationError(u"{:s}._read({!r}, {:#x}) : Unable to decode contents for {:#x} at {:#x}. The data that failed to decode is {!r}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, key, ea, encdata))

        try:
            result = cls.marshaller.loads(data)
        except:
            raise internal.exceptions.SerializationError(u"{:s}._read({!r}, {:#x}) : Unable to unmarshal contents for {:#x} at {:#x}. The data that failed to be unmarshalled is {!r}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, key, ea, data))
        return result

    @classmethod
    def _write(cls, target, ea, value):
        '''Writes a dictionary to the specified object'''
        node, key = tagging.node(), cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._write({!r}, {:#x}, {!r}) : Unable to find a function for target ({!r}) at {:#x}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, value, key, ea))

        # erase cache and blob if no data is specified
        if not value:
            try:
                ok = cls._write_header(target, ea, None)
                if not ok:
                    logging.debug(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to remove address from sup cache with the key {:#x}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, internal.utils.string.repr(value), key))
            finally:
                return internal.netnode.blob.remove(key, cls.btag)

        # update blob for given address
        res = value
        try:
            data = cls.marshaller.dumps(res)
        except:
            raise internal.exceptions.SerializationError(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to marshal contents for {:#x} at {:#x}. The data that failed to be marshalled is {!r}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, internal.utils.string.repr(value), key, ea, res))

        try:
            encdata, sz = cls.codec.encode(data)
        except:
            raise internal.exceptions.SerializationError(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to encode contents for {:#x} at {:#x}. The data that failed to be encoded is {!r}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, internal.utils.string.repr(value), key, ea, data))

        if sz != len(data):
            raise internal.exceptions.SizeMismatchError(u"{:s}._write({!r}, {:#x}, {!s}) : The number of bytes that was encoded ({:#x}) did not match the expected size ({:+#x}).".format('.'.join(('internal', __name__, cls.__name__)), target, ea, internal.utils.string.repr(value), sz, len(data)))

        # write blob
        try:
            ok = internal.netnode.blob.set(key, cls.btag, encdata)
            if not ok: raise AssertionError # XXX: use an explicit exception
        except:
            raise internal.exceptions.DisassemblerError(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to set contents for {:#x} at {:#x}. The data that failed to be set is {!r}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, internal.utils.string.repr(value), key, ea, encdata))

        # update sup cache with keys
        res = set(value.viewkeys())
        try:
            ok = cls._write_header(target, ea, res)
            if not ok: raise AssertionError # XXX: use an explicit exception
        except:
            logging.fatal(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to set address to sup cache with the key {:#x}.".format('.'.join(('internal', __name__, cls.__name__)), target, ea, internal.utils.string.repr(value), key))
        return ok

    @classmethod
    def iterate(cls):
        node = tagging.node()
        for ea in internal.netnode.sup.fiter(node):
            encdata = internal.netnode.sup.get(node, ea)
            data, sz = cls.codec.decode(encdata)
            if len(encdata) != sz:
                logging.warn(u"{:s}.iterate() : Failed decoding tag names out of sup cache for {:#x} due to the length of encoded data ({:#x}) not matching the expected size ({:#x}).".format('.'.join(('internal', __name__, cls.__name__)), ea, len(encdata), sz))
            res = cls.marshaller.loads(data)
            yield ea, res
        return

    @classmethod
    def inc(cls, address, name, **target):
        res = cls._read(target.get('target', None), address) or {}
        state, cache = res.get(cls.__tags__, {}), res.get(cls.__address__, {})

        state[name] = refs = state.get(name, 0) + 1
        cache[address] = cache.get(address, 0) + 1

        if state: res[cls.__tags__] = state
        else: del res[cls.__tags__]

        if cache: res[cls.__address__] = cache
        else: del res[cls.__address__]

        cls._write(target.get('target', None), address, res)
        return refs

    @classmethod
    def dec(cls, address, name, **target):
        res = cls._read(target.get('target', None), address) or {}
        state, cache = res.get(cls.__tags__, {}), res.get(cls.__address__, {})

        refs, count = state.pop(name, 0) - 1, cache.pop(address, 0) - 1
        if refs > 0:
            state[name] = refs

        if count > 0:
            cache[address] = count

        if state: res[cls.__tags__] = state
        else: res.pop(cls.__tags__, None)

        if cache: res[cls.__address__] = cache
        else: res.pop(cls.__address__, None)

        cls._write(target.get('target', None), address, res)
        return refs

    @classmethod
    def name(cls, address, **target):
        '''Return all the tag names for the specified function'''
        res = cls._read(target.get('target', None), address) or {}
        res = res.get(cls.__tags__, {})
        return set(res.viewkeys())

    @classmethod
    def address(cls, address, **target):
        '''Return all the tag address for the specified function'''
        res = cls._read(target.get('target', None), address) or {}
        res = res.get(cls.__address__, {})
        return sorted(res.viewkeys())

    @classmethod
    def set_name(cls, address, name, count, **target):
        state = cls._read(target.get('target', None), address) or {}

        res = state.get(cls.__tags__, {})
        if count > 0:
            res[name] = count
        else:
            res.pop(name, None)

        if res:
            state[cls.__tags__] = res
        else:
            state.pop(cls.__tags__, None)

        ok = cls._write(target.get('target', None), address, state)
        if ok:
            return state
        raise internal.exceptions.ReadOrWriteError(u"{:s}.set_name({:#x}, {!r}, {:d}{:s}) : Unable to write name to address {:#x}.".format('.'.join(('internal', __name__, cls.__name__)), address, name, count, ', {:s}'.format(internal.utils.string.kwargs(target)) if target else '', address))

    @classmethod
    def set_address(cls, address, count, **target):
        state = cls._read(target.get('target', None), address) or {}

        res = state.get(cls.__address__, {})
        if count > 0:
            res[address] = count
        else:
            res.pop(address, None)

        if res:
            state[cls.__address__] = res
        else:
            state.pop(cls.__address__, None)

        ok = cls._write(target.get('target', None), address, state)
        if ok:
            return state
        raise internal.exceptions.ReadOrWriteError(u"{:s}.set_address({:#x}, {:d}{:s}) : Unable to write name to address {:#x}.".format('.'.join(('internal', __name__, cls.__name__)), address, count, ', {:s}'.format(internal.utils.string.kwargs(target)) if target else '', address))

class globals(tagging):
    '''Tagging for a function-tag or a global'''

    ## FIXME: for each global/function
    # netnode.alt[address] = refcount
    # netnode.hash[name] = refcount

    @classmethod
    def inc(cls, address, name):
        node = tagging.node()

        cName = (internal.netnode.hash.get(node, name, type=int) or 0) + 1
        cAddress = (internal.netnode.alt.get(node, address) or 0) + 1

        internal.netnode.hash.set(node, name, cName)
        internal.netnode.alt.set(node, address, cAddress)

        return cName

    @classmethod
    def dec(cls, address, name):
        node = tagging.node()

        cName = (internal.netnode.hash.get(node, name, type=int) or 1) - 1
        cAddress = (internal.netnode.alt.get(node, address) or 1) - 1

        if cName < 1:
            internal.netnode.hash.remove(node, name)
        else:
            internal.netnode.hash.set(node, name, cName)

        if cAddress < 1:
            internal.netnode.alt.remove(node, address)
        else:
            internal.netnode.alt.set(node, address, cAddress)

        return cName

    @classmethod
    def name(cls):
        '''Return all the tag names in the specified database (globals and func-tags)'''
        node = tagging.node()
        return set(internal.netnode.hash.fiter(node))

    @classmethod
    def address(cls):
        '''Return all the tag addresses in the specified database (globals and func-tags)'''
        return sorted(ea for ea, _ in internal.netnode.alt.fiter(tagging.node()))

    @classmethod
    def set_name(cls, name, count):
        node = tagging.node()
        res = internal.netnode.hash.get(node, name, type=int)
        internal.netnode.hash.set(node, name, count)
        return res

    @classmethod
    def set_address(cls, address, count):
        node = tagging.node()
        res = internal.netnode.alt.get(node, address)
        internal.netnode.alt.set(node, address, count)
        return res

