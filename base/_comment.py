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
    def __database_inited__(cls, is_new_database, idc_script):
        cls.node()

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
    # netnode.sup[fn.startEA] = pickle.dumps({'__address__','__tags__')

    @classmethod
    def _key(cls, ea):
        '''Converts address to a key that's used to store arbitrary data'''
        res = idaapi.get_func(ea)
        return res.startEA if res else None

    @classmethod
    def _read(cls, ea):
        '''Reads a dictionary from the specific object'''
        node, key = tagging.node(), cls._key(ea)
        if key is None:
            raise LookupError(ea)

        # check to see if using old sup version
        res = internal.netnode.sup.get(node, key)
        if res is not None:
            try:
                # check if it's not corrupted
                marshal.loads(cls.codec.decode(res))
            except:
                pass
            else:
                # if so, then re-assign it to function's blob
                internal.netnode.blob.set(key, idaapi.stag, res)
            internal.netnode.sup.remove(node, key)

        encdata = internal.netnode.blob.get(key, idaapi.stag)
        #encdata = internal.netnode.sup.get(node, key)
        if encdata is None:
            return None

        data,sz = cls.codec.decode(encdata)
        if len(encdata) != sz:
            raise ValueError((sz,len(encdata)))
        return cls.marshaller.loads(data)

    @classmethod
    def _write(cls, ea, value):
        '''Writes a dictionary to the specified object'''
        node, key = tagging.node(), cls._key(ea)
        if key is None:
            raise LookupError(ea)

        if not value:
            return internal.netnode.blob.remove(key, idaapi.stag)
            #return internal.netnode.sup.remove(node, key)

        data = cls.marshaller.dumps(value)
        encdata,sz = cls.codec.encode(data)
        if sz != len(data):
            raise ValueError((sz,len(data)))
        return internal.netnode.blob.set(key, idaapi.stag, encdata)
        #return internal.netnode.sup.set(node, key, encdata)

    @classmethod
    def iterate(cls):
        for fn in internal.netnode.sup.fiter(tagging.node()):
            yield fn
        return

    @classmethod
    def inc(cls, address, name):
        res = cls._read(address) or {}
        state, cache = res.get(cls.__tags__, {}), res.get(cls.__address__, {})

        state[name] = refs = state.get(name, 0) + 1
        cache[address] = cache.get(address, 0) + 1

        if state: res[cls.__tags__] = state
        else: del res[cls.__tags__]

        if cache: res[cls.__address__] = cache
        else: del res[cls.__address__]

        cls._write(address, res)
        return refs

    @classmethod
    def dec(cls, address, name):
        res = cls._read(address) or {}
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

        cls._write(address, res)
        return refs

    @classmethod
    def name(cls, address):
        '''Return all the tag names for the specified function'''
        res = cls._read(address) or {}
        res = res.get(cls.__tags__, {})
        return set(res.viewkeys())

    @classmethod
    def address(cls, address):
        '''Return all the tag address for the specified function'''
        res = cls._read(address) or {}
        res = res.get(cls.__address__, {})
        return sorted(res.viewkeys())

    @classmethod
    def set_name(cls, address, name, count):
        state = cls._read(address) or {}

        res = state.get(cls.__tags__, {})
        if count > 0:
            res[name] = count
        else:
            res.pop(name, None)

        if res:
            state[cls.__tags__] = res
        else:
            state.pop(cls.__tags__, None)

        ok = cls._write(address, state)
        assert ok
        return state

    @classmethod
    def set_address(cls, address, count):
        state = cls._read(address) or {}

        res = state.get(cls.__address__,{})
        if count > 0:
            res[address] = count
        else:
            res.pop(address, None)

        if res:
            state[cls.__address__] = res
        else:
            state.pop(cls.__address__, None)

        ok = cls._write(address, state)
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

class address_hook(object):
    @classmethod
    def _is_repeatable(cls, ea):
        f = idaapi.get_func(ea)
        return True if f is None else False

    @classmethod
    def _update_refs(cls, ea, old, new):
        f = idaapi.get_func(ea)
        for key in old.viewkeys() ^ new.viewkeys():
            if key not in new:
                if f: contents.dec(ea, key)
                else: globals.dec(ea, key)
            if key not in old:
                if f: contents.inc(ea, key)
                else: globals.inc(ea, key)
            continue
        return

    @classmethod
    def _create_refs(cls, ea, res):
        f = idaapi.get_func(ea)
        for key in res.viewkeys():
            if f: contents.inc(ea, key)
            else: globals.inc(ea, key)
        return

    @classmethod
    def _delete_refs(cls, ea, res):
        f = idaapi.get_func(ea)
        for key in res.viewkeys():
            if f: contents.dec(ea, key)
            else: globals.dec(ea, key)
        return

    @classmethod
    def _event(cls):
        while True:
            # cmt_changing event
            ea,rpt,new = (yield)
            old = idaapi.get_cmt(ea, rpt)
            f,o,n = idaapi.get_func(ea),decode(old),decode(new)

            # update references before we update the comment
            cls._update_refs(ea, o, n)

            # wait for cmt_changed event
            newea,nrpt,none = (yield)

            # now fix the comment the user typed
            if (newea,nrpt,none) == (ea,rpt,None):
                ncmt,repeatable = idaapi.get_cmt(ea, rpt), cls._is_repeatable(ea)

                if (ncmt or '') != new:
                    logging.warn('internal.{:s}.event : Comment from event is different from database : {:x} : {!r} != {!r}'.format('.'.join((__name__,cls.__name__)), ea, new, ncmt))

                # delete it if it's the wrong type
#                if nrpt != repeatable:
#                    idaapi.set_cmt(ea, '', nrpt)

#                # write the tag back to the address
#                if check(new): idaapi.set_cmt(ea, encode(n), repeatable)
#                # write the comment back if it's non-empty
#                elif new: idaapi.set_cmt(ea, new, repeatable)
#                # otherwise, remove it's reference since it's being deleted
#                else: cls._delete_refs(ea, n)

                if check(new): idaapi.set_cmt(ea, encode(n), rpt)
                elif new: idaapi.set_cmt(ea, new, rpt)
                else: cls._delete_refs(ea, n)

                continue

            # if the changed event doesn't happen in the right order
            logging.fatal("internal.{:s}.event : Comment events are out of sync, updating tags from previous comment. : {!r} : {!r}".format('.'.join((__name__,cls.__name__)), o, n))

            # delete the old comment
            cls._delete_refs(ea, o)
            idaapi.set_cmt(ea, '', rpt)
            logging.warn("internal.{:s}.event : Previous comment at {:x} : {!r}".format('.'.join((__name__,cls.__name__)), o))

            # new comment
            new = idaapi.get_cmt(newea, nrpt)
            n = decode(new)
            cls._create_refs(newea, n)

            continue
        return

    @classmethod
    def changing(cls, ea, repeatable_cmt, newcmt):
        oldcmt = idaapi.get_cmt(ea, repeatable_cmt)
        cls.event.send((ea, bool(repeatable_cmt), newcmt))

    @classmethod
    def changed(cls, ea, repeatable_cmt):
        newcmt = idaapi.get_cmt(ea, repeatable_cmt)
        cls.event.send((ea, bool(repeatable_cmt), None))

class global_hook(object):
    @classmethod
    def _update_refs(cls, fn, old, new):
        for key in old.viewkeys() ^ new.viewkeys():
            if key not in new:
                globals.dec(fn.startEA, key)
            if key not in old:
                globals.inc(fn.startEA, key)
            continue
        return

    @classmethod
    def _create_refs(cls, fn, res):
        for key in res.viewkeys():
            globals.inc(fn.startEA, key)
        return

    @classmethod
    def _delete_refs(cls, fn, res):
        for key in res.viewkeys():
            globals.dec(fn.startEA, key)
        return

    @classmethod
    def _event(cls):
        while True:
            # cmt_changing event
            ea,rpt,new = (yield)
            fn = idaapi.get_func(ea)
            old = idaapi.get_func_cmt(fn, rpt)
            o,n = decode(old),decode(new)

            # update references before we update the comment
            cls._update_refs(fn, o, n)

            # wait for cmt_changed event
            newea,nrpt,none = (yield)

            # now we can fix the user's new coment
            if (newea,nrpt,none) == (ea,rpt,None):
                ncmt = idaapi.get_func_cmt(fn, rpt)

                if (ncmt or '') != new:
                    logging.warn('internal.{:s}.event : Comment from event is different from database : {:x} : {!r} != {!r}'.format('.'.join((__name__,cls.__name__)), ea, new, ncmt))

                # if it's non-repeatable, then fix it.
#                if not nrpt:
#                    idaapi.set_func_cmt(fn, '', nrpt)

#                # write the tag back to the function
#                if check(new): idaapi.set_func_cmt(fn, encode(n), True)
#                # otherwise, write the comment back as long as it's valid
#                elif new: idaapi.set_func_cmt(fn, new, True)
#                # otherwise, the user has deleted it..so update it's refs.
#                else: cls._delete_refs(fn, n)

                # write the tag back to the function
                if check(new): idaapi.set_func_cmt(fn, encode(n), rpt)
                elif new: idaapi.set_func_cmt(fn, new, rpt)
                else: cls._delete_refs(fn, n)
                continue

            # if the changed event doesn't happen in the right order
            logging.fatal("internal.{:s}.event : Comment events are out of sync, updating tags from previous comment. : {!r} : {!r}".format('.'.join((__name__,cls.__name__)), o, n))

            # delete the old comment
            cls._delete_refs(fn, o)
            idaapi.set_func_cmt(fn, '', rpt)
            logging.warn("internal.{:s}.event : Previous comment at {:x} : {!r}".format('.'.join((__name__,cls.__name__)), o))

            # new comment
            newfn = idaapi.get_func(newea)
            new = idaapi.get_func_cmt(newfn, nrpt)
            n = decode(new)
            cls._create_refs(newfn, n)

            continue
        return

    @classmethod
    def changing(cls, cb, a, cmt, repeatable):
        fn = idaapi.get_func(a.startEA)
        oldcmt = idaapi.get_func_cmt(fn, repeatable)
        cls.event.send((fn.startEA, bool(repeatable), cmt))

    @classmethod
    def changed(cls, cb, a, cmt, repeatable):
        fn = idaapi.get_func(a.startEA)
        newcmt = idaapi.get_func_cmt(fn, repeatable)
        cls.event.send((fn.startEA, bool(repeatable), None))

if not hasattr(address_hook, 'event'):
    address_hook.event = address_hook._event(); next(address_hook.event)
if not hasattr(global_hook, 'event'):
    global_hook.event = global_hook._event(); next(global_hook.event)
