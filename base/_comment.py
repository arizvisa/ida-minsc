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

import itertools,functools,operator
import collections,heapq,string
import six,logging

import internal,idaapi
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
                return
            yield ch
    except StopIteration: pass
    raise KeyError

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
        logging.warn("{:s}.parse_line : Assuming tag {!r} is of type _str. : {!r}".format( '.'.join(("internal", __name__)), key, value))
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

def check(data):
    res = map(iter, (data or '').split('\n'))
    try:
        map(parse_line, res)
    except (KeyError,StopIteration):
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
        logging.debug("{:s}.{:s}.init_tagcache : Initialized tagcache with netnode {!r} : {:x}".format('.'.join(("internal",__name__)), cls.__name__, cls.__node__, cls.__nodeid__))

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
    # netnode.blob[fn.startEA, btag] = marshal.dumps({'name','address'})
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
            raise LookupError("{:s}.{:s}._read_header : Unable to find a function for {:x} at {:x}".format( '.'.join(("internal", __name__)), cls.__name__, key, ea))

        encdata = internal.netnode.sup.get(key, cls.btag)
        if encdata is None:
            return None

        try:
            data,sz = cls.codec.decode(encdata)
            if len(encdata) != sz:
                raise ValueError((sz,len(encdata)))
        except:
            raise IOError("{:s}.{:s}._read_header : Unable to decode contents for {:x} at {:x} : {!r}".format( '.'.join(("internal", __name__)), cls.__name__, key, ea, encdata))

        try:
            result = cls.marshaller.loads(data)
        except:
            raise IOError("{:s}.{:s}._read_header : Unable to unmarshal contents for {:x} at {:x}: {!r}".format( '.'.join(("internal", __name__)), cls__name__, key, ea, data))
        return result

    @classmethod
    def _write_header(cls, target, ea, value):
        node, key = tagging.node(), cls._key(ea) if target is None else target
        if key is None:
            raise LookupError("{:s}.{:s}._write_header : Unable to find a function for {:x} at {:x}".format( '.'.join(("internal", __name__)), cls.__name__, key, ea))

        if not value:
            ok = internal.netnode.sup.remove(node, key)
            return bool(ok)

        try:
            data = cls.marshaller.dumps(value)
        except:
            raise IOError("{:s}.{:s}._write_header : Unable to marshal contents for {:x} at {:x} : {!r}".format( '.'.join(("internal", __name__)), cls.__name__, key, ea, value))

        try:
            encdata,sz = cls.codec.encode(data)
            if sz != len(data):
                raise ValueError((value,sz,len(data)))
        except:
            raise IOError("{:s}.{:s}._write_header : Unable to encode contents for {:x} at {:x} : {!r}".format( '.'.join(("internal", __name__)), cls.__name__, key, ea, data))

        if len(encdata) > 1024:
            logging.warn("{:s}.{:s}._write_header : Too many tags within function. Size must be < 0x400. Ignoring. : {:x}".format('.'.join(("internal", __name__)), cls.__name__, len(encdata)))

        ok = internal.netnode.sup.set(node, key, encdata)
        return bool(ok)

    @classmethod
    def _read(cls, target, ea):
        '''Reads a dictionary from the specific object'''
        node, key = tagging.node(), cls._key(ea) if target is None else target
        if key is None:
            raise LookupError("{:s}.{:s}._read : Unable to find a function for {:x} at {:x}".format( '.'.join(("internal", __name__)), cls.__name__, key, ea))

        encdata = internal.netnode.blob.get(key, cls.btag)
        if encdata is None:
            return None

        try:
            data,sz = cls.codec.decode(encdata)
            if len(encdata) != sz:
                raise ValueError((sz,len(encdata)))
        except:
            raise IOError("{:s}.{:s}._read : Unable to decode contents for {:x} at {:x} : {!r}".format( '.'.join(("internal", __name__)), cls.__name__, key, ea, encdata))
        
        try:
            result = cls.marshaller.loads(data)
        except:
            raise IOError("{:s}.{:s}._read : Unable to unmarshal contents for {:x} at {:x}: {!r}".format( '.'.join(("internal", __name__)), cls__name__, key, ea, data))
        return result

    @classmethod
    def _write(cls, target, ea, value):
        '''Writes a dictionary to the specified object'''
        node, key = tagging.node(), cls._key(ea) if target is None else target
        if key is None:
            raise LookupError("{:s}.{:s}._write : Unable to find a function for {:x} at {:x}".format( '.'.join(("internal", __name__)), cls.__name__, key, ea))

        # erase cache and blob if no data is specified
        if not value:
            try:
                ok = cls._write_header(target, ea, None)
                if not ok:
                    logging.info("{:s}.{:s}._write : Unable to remove address from sup cache. : {:x}".format('.'.join(("internal", __name__)), cls.__name__, key))
            finally:
                return internal.netnode.blob.remove(key, cls.btag)

        # update blob for given address
        res = value
        try:
            data = cls.marshaller.dumps(res)
        except:
            raise IOError("{:s}.{:s}._write : Unable to marshal contents for {:x} at {:x} : {!r}".format(__name__, cls.__name__, key, ea, res))

        try:
            encdata,sz = cls.codec.encode(data)
        except:
            raise IOError("{:s}.{:s}._write : Unable to encode contents for {:x} at {:x} : {!r}".format(__name__, cls.__name__, key, ea, data))
        if sz != len(data):
            raise ValueError((res,sz,len(data)))

        # write blob
        try:
            ok = internal.netnode.blob.set(key, cls.btag, encdata)
            assert ok
        except:
            raise IOError("{:s}.{:s}._write : Unable to set contents for {:x} at {:x} : {!r}".format(__name__, cls.__name__, key, ea, encdata))

        # update sup cache with keys
        res = set(value.viewkeys())
        try:
            ok = cls._write_header(target, ea, res)
            assert ok
        except:
            logging.fatal("{:s}.{:s}._write : Unable to set address to sup cache. : {:x}".format('.'.join(("internal", __name__)), cls.__name__, key))
        return ok

    @classmethod
    def iterate(cls):
        node = tagging.node()
        for ea in internal.netnode.sup.fiter(tagging.node()):
            encdata = internal.netnode.sup.get(node, ea)
            data,sz = cls.codec.decode(encdata)
            if sz != len(encdata):
                logging.warn("Internal.{:s}.iterate : Unable to decode tag names out of sup cache for {:x} : {:x} != {:x}".format('.'.join((__name__,cls.__name__)), ea, len(encdata), sz))
            res = cls.marshaller.loads(data)
            yield ea, res
        return

    @classmethod
    def inc(cls, address, name, **target):
        res = cls._read(target.get('target',None), address) or {}
        state, cache = res.get(cls.__tags__, {}), res.get(cls.__address__, {})

        state[name] = refs = state.get(name, 0) + 1
        cache[address] = cache.get(address, 0) + 1

        if state: res[cls.__tags__] = state
        else: del res[cls.__tags__]

        if cache: res[cls.__address__] = cache
        else: del res[cls.__address__]

        cls._write(target.get('target',None), address, res)
        return refs

    @classmethod
    def dec(cls, address, name, **target):
        res = cls._read(target.get('target',None), address) or {}
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

        cls._write(target.get('target',None), address, res)
        return refs

    @classmethod
    def name(cls, address, **target):
        '''Return all the tag names for the specified function'''
        res = cls._read(target.get('target',None), address) or {}
        res = res.get(cls.__tags__, {})
        return set(res.viewkeys())

    @classmethod
    def address(cls, address, **target):
        '''Return all the tag address for the specified function'''
        res = cls._read(target.get('target',None), address) or {}
        res = res.get(cls.__address__, {})
        return sorted(res.viewkeys())

    @classmethod
    def set_name(cls, address, name, count, **target):
        state = cls._read(target.get('target',None), address) or {}

        res = state.get(cls.__tags__, {})
        if count > 0:
            res[name] = count
        else:
            res.pop(name, None)

        if res:
            state[cls.__tags__] = res
        else:
            state.pop(cls.__tags__, None)

        ok = cls._write(target.get('target',None), address, state)
        assert ok
        return state

    @classmethod
    def set_address(cls, address, count, **target):
        state = cls._read(target.get('target',None), address) or {}

        res = state.get(cls.__address__,{})
        if count > 0:
            res[address] = count
        else:
            res.pop(address, None)

        if res:
            state[cls.__address__] = res
        else:
            state.pop(cls.__address__, None)

        ok = cls._write(target.get('target',None), address, state)
        assert ok
        return state
        
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
        return sorted(ea for ea,_ in internal.netnode.alt.fiter(tagging.node()))

    @classmethod
    def set_name(cls, name, count):
        res = internal.netnode.hash.get(tagging.node(), name, type=int)
        internal.netnode.hash.set(tagging.node(), name, count)
        return res

    @classmethod
    def set_address(cls, address, count):
        res = internal.netnode.alt.get(tagging.node(), address)
        internal.netnode.alt.set(tagging.node(), address, count)
        return res

