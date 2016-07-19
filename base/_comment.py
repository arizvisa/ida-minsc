'''
Abstraction around IDA's comments to allow one to store arbitrary python objects within them. These encoded python objects follow a constraint in that they also must be human-readable.

Each comment stores a dictionary that has the following format:

    [key1] value1
    [key2] value2
    ...

If a comment does not follow the specified format, then it is assumed that the comment's value is unencoded and it's key is "" (empty). This implies that if your comment at an address is simply "HeapHandle", then it's dictionary is {'':'HeapHandle'}. Most basic pythonic objects can be stored, if one needs to store a more complex type it is suggested that the developer either marshal/pickle it and then base64 encode it at a given address w/ a key.

Some value types are encoded in order to retain any specific information about the value as well as to allow a user to read the value's immediate contents. For example:

    4021 -> 0xfb5
    -100 -> -0x64
    0.5 -> float(0.5)

    'hello world\nhow\'re ya' -> hello world\nhow're ya
    {10,20,30} -> set([10, 20, 30])

Lists and Dictionary types are stored as-is. Integral types are always portrayed in hexadecimal form as IDA uses hexadecimal everywhere. Despite one being allowed to specify a comment that's a decimal or an octal number, when encoding a tag it will always be in a hexadecimal format. This way if a user has tagged an address in a comment, they may double-click on it to convince IDA to follow it.

String types have the ability to escape certain characters.  The characters that have special meaning are '\n', '\r', and '\t'. Similarly if a backslash is escaped, it will result in a single '\'. If any other character is prefixed with a backslash, it will decode into a character prefixed with a backslash. This is different from what one would expect in that all characters might be escaped but is done so that one would not need to recursively escape and unescape strings that are stored.
'''

import sys
import itertools,functools,operator
import collections,heapq,string
import six,logging

import idaapi

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
                raise KeyError(i, n)
            self = self[n]
            yield self
        return

    def get(self, symbols):
        for i, n in enumerate(self.descend(symbols)):
            continue
        if isinstance(n, trie):
            raise KeyError(i, n)
        return n

    def find(self, symbols):
        for i, n in enumerate(self.descend(symbols)):
            if not isinstance(n, trie):
                return n
            continue
        raise KeyError(i, n)

    def dump(self):
        cls = self.__class__
        # FIXME: doesn't support recursion
        def stringify(node, indent=0, tab='  '):
            data = (k for k,v in node.viewitems() if not isinstance(v, trie))
            result = []
            for k in data:
                result.append('{:s}{!r} -> {!r}'.format(tab * indent, k, node[k]))

            branches = [k for k,v in node.viewitems() if isinstance(v, trie)]
            for k in branches:
                result.append('{:s}{!r}'.format(tab * indent, k))
                branch_data = stringify(node[k], indent+1, tab=tab)
                result.extend(branch_data)
            return result
        return '\n'.join(('{!r}({:d})'.format(cls, self.id),'\n'.join(stringify(self))))

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
        t = instance.__class__
        if t not in cls.state:
            t = next((k for k in cls.state if issubclass(t, k)), None)
            if not t: return None
        return next((k for k in cls.state[t] if k.type(instance)), None)

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
        return '-0x{:x}'.format(abs(instance)) if instance < 0 else '0x{:x}'.format(abs(instance))

@cache.register(object, trie.star(' \t'), *'float(')
class _float(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, float)
    @classmethod
    def encode(cls, instance):
        return 'float({:f})'.format(instance)

@cache.register(str)
class _str(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, str)

    @staticmethod
    def _unescape(iterable):
        try:
            while True:
                ch = next(iterable)
                if ch == '\\':
                    ch = next(iterable)
                    if   ch == '\\': yield '\\'
                    elif ch == 'n' : yield '\n'
                    elif ch == 'r' : yield '\r'
                    elif ch == 't' : yield '\t'
                    #else           : yield ch
                    else           : yield '\\'; yield ch
                    continue
                yield ch
        except StopIteration: pass
    @staticmethod
    def _escape(iterable):
        try:
            while True:
                ch = next(iterable)
                if   ch == '\\': yield '\\'; yield '\\'
                elif ch == '\n': yield '\\'; yield 'n'
                elif ch == '\r': yield '\\'; yield 'r'
                elif ch == '\t': yield '\\'; yield 't'
                else           : yield ch
        except StopIteration: pass

    @classmethod
    def decode(cls, data):
        res = str(data).lstrip()
        return str().join(cls._unescape(iter(res)))
    @classmethod
    def encode(cls, instance):
        # FIXME: strip out newlines
        res = cls._escape(iter(instance))
        return '{:s}'.format(str().join(res))

@cache.register(unicode, trie.star(' \t'), *"u'")
class _unicode(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, str)

@cache.register(dict, trie.star(' \t'), '{')
class _dict(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, dict)

@cache.register(list, trie.star(' \t'), '[')
class _list(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, list)

@cache.register(tuple, trie.star(' \t'), '(')
class _tuple(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, tuple)

@cache.register(set, trie.star(' \t'), *'set([')
class _set(default):
    @classmethod
    def type(cls, instance):
        return isinstance(instance, set)

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
                break
            yield ch
    except StopIteration: pass

def parse_line(iterable):
    ch = next(iterable)
    if ch != '[': raise KeyError
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
        res = _str.decode(value)
        logging.warn("internal.{:s}.parse_line : Assuming tag {!r} is of type _str. : {!r}".format(__name__, key, value))
        #raise ValueError("Unable to decode data with {!r} : {!r}".format(t, value))
    return key, res

def emit_line(key, value):
    escape = {
        '\\' : r'\\',
        '['  : r'\[',
        ']'  : r'\]',
        '\n' : r'\n',
        '\r' : r'\r',
        '\t' : r'\t',
    }
    k = str().join(escape.get(n, n) for n in key)
    t = cache.by(value)
    return '[{:s}] {:s}'.format(k, t.encode(value))

### Encoding and decoding of a comment
def decode(data):
    res = {}
    try:
        for line in (data or '').split('\n'):
            try: k, v = parse_line(iter(line))
            except KeyError: k, v = '', line
            res[k] = v
    except StopIteration: pass
    return res

def encode(dict):
    res = []
    for k,v in (dict or {}).iteritems():
        res.append(emit_line(k,v))
    return '\n'.join(res)

### Tag reference counting
class tag(object):
    __tags__, __address__ = '__tags__', '__address__'

    # FIXME: instead of calculating this everytime, it'd be best to use an on-database hook
    #        and assign it somewhere
    @classmethod
    def _top(cls, ea):
        fn = idaapi.get_func(ea)
        inside = fn.startEA

        res = idaapi.get_inf_structure()
        outside = res.maxEA if idaapi.get_func(res.minEA) else res.minEA

        return outside if fn is None else inside

    # FIXME: storing these reference counts in a comment is a pretty
    #        horrible place to put them. find some other place to stash it.
    @classmethod
    def _read(cls, ea):
        comment = sys.modules['database'].comment
        res = comment(ea, repeatable=False) or ''
        return decode(res)

    @classmethod
    def _write(cls, ea, value):
        comment = sys.modules['database'].comment
        res = encode(value)
        return comment(ea, res, repeatable=False)

    @classmethod
    def inc(cls, address, name):
        ea = cls._top(address)

        # grab result
        res = cls._read(ea)
        state, cache = res.get(cls.__tags__, {}), res.get(cls.__address__, {})

        # backwards compatibility
        if isinstance(state, set):
            logging.warn("internal.{:s}.inc : Using deprecated tag cache syntax : {!r}".format( '.'.join((__name__,cls.__name__)), state))
            state.add(name)
            res[cls.__tags__] = state
            cls._write(ea, res)
            return 1

        # increase key reference count
        refs = state.get(name, 0) + 1
        state[name] = refs

        # update cache
#        cache[address] = cache.get(address, 0) + 1

        # update result
        if state: res[cls.__tags__] = state
        else: del res[cls.__tags__]
#        if cache: res[cls.__address__] = cache
#        else: del res[cls.__address__]

        cls._write(ea, res)
        return refs

    @classmethod
    def dec(cls, address, name):
        ea = cls._top(address)

        # grab result
        res = cls._read(ea)
        state, cache = res.get(cls.__tags__, {}), res.get(cls.__address__, {})

        # backwards compatibility
        if isinstance(state, set):
            logging.warn("internal.{:s}.dec : Using deprecated tag cache syntax : {!r}".format( '.'.join((__name__,cls.__name__)), state))
            state.add(name)
            res[cls.__tags__] = state
            cls._write(ea, res)
            return 1

        # decrease key reference count
        refs = state.pop(name) - 1
        if refs > 0:
            state[name] = refs

        # remove from address cache if it's gone
#        count = cache.pop(address) - 1
#        if count > 0:
#            cache[address] = count

        # update result
        if state: res[cls.__tags__] = state
        else: del res[cls.__tags__]
#        if cache: res[cls.__address__] = cache
#        else: del res[cls.__address__]

        cls._write(ea, res)
        return refs

    @classmethod
    def get(cls, ea):
        ea = cls._top(ea)
        res = cls._read(ea)
        res = res.get(cls.__tags__, {})
        return set(res.viewkeys()) if isinstance(res, dict) else set(res)

    @classmethod
    def address(cls, ea):
        ea = cls._top(ea)
        res = cls._read(ea)
        res = res.get(cls.__address__, {})
        return sorted(res.viewkeys())

