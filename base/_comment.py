'''
tagged-comments plugin.
provides serialization/deserialization from arbitrary types to fit within ida's comments
[arizvisa@tippingpoint.com]
'''
import __builtin__,six

def tokens(input):
    input = iter(input)

    ### '['
    char = input.next()
    assert char == '[', 'unexpected token {:s}'.format(char)
    yield char

    ### key
    res = ''
    char = input.next()
    while char != ']':
        res += char
        char = input.next()
    yield res

    ### ']'
    yield char

    ### ' ' '\t'
    while True:
        res = input.next()
        if res in ' \t':
            continue
        break
    
    ### value
    yield res+''.join(list(input))

def getKVFromString(string):
    res = list( tokens(string) )
    l = len(res)
    if l == 3:
        assert (res[0] == '[') and (res[2] == ']')
        return (res[1], '')

    assert (l==4) and (res[0] == '[') and (res[2] == ']')
    return (res[1], res[-1])

def getStringFromKV(key, value):
    return '[{:s}] {:s}'.format(key, value)

def getIntFromKV(tuple):
    key, value = tuple
    return '[{:s}] {:x}'.format(key, value)

def IntifyString(value):
    if value[:2] == '0x':
        return int(value[2:], 16) 
    if value[-1:] == 'h':
        return int(value[:-1], 16) 
    if value[-1:] == 'd':
        return int(value[:-1], 10) 
    if value[-1:] == 'b':
        return int(value[:-1], 2) 
    return int(value)

### our stars
def serializeKeyValue(k, v):
    #if k == 'address':
    #    return '{:08x}'.format(int(v))
    if isinstance(v, six.integer_types):
        if v < 0:
            return '-0x{:x}'.format(-int(v))
        return '0x{:x}'.format(int(v))
    elif isinstance(v, dict):
        # due to how bad this code is, i'm not allowing myself to add support for various types
        raise NotImplementedError("Please don't store dicts using this code. Thanks.")
    elif isinstance(v, (list,set)):
        try:
            return '[ {:s} ]'.format(','.join(map(hex,v)))
        except:
            pass
        return repr(v)
    return str(v)

def toList(string):
    '''
    converts the following looking string into a list of numbers or strings

    [type] void*
    [value] 0x80ad
    [synopsis] ok....
    '''
    if string is None:      # always return something
        string = ''

    try:
        rows = [n for n in string.split('\n') if n]
        stritems = [getKVFromString(n) for n in rows]

    except AssertionError:
#        stritems = [('untagged-value', string)]
        stritems = [('', string)]

    items = []
    for k,v in stritems:
        try:
            if v.startswith('['):
                v = eval(v)
            else:
                v = IntifyString(v)
        except:
            pass
        items.append( (k,v) )
    return items

def toDict(string):
    items = toList(string)

    # pull out/rename duplicates
    all,blah = set(),set()
    for k,v in items:
        if k in all:
            blah.add(k)
            continue
        all.add(k)
    
    # fix up duplicates
    res = []
    for i,(k,v) in enumerate(items):
        if k in blah:
            k = '{:s}_{:x}'.format(k, i)
        res.append((k,getattr(__builtin__,v) if isinstance(v,basestring) and hasattr(__builtin__,v) else v))

    # done
    return dict(res)

def toString(dict):
    '''
    converts a dictionary to it's string representation.

    {'synopsis': 'ok....', 'type': 'void*', 'value': 32941}

    to

    [type] void*
    [value] 0x80ad
    [synopsis] ok....
    '''
    rawitems = dict.items()
    stritems = [(k, serializeKeyValue(k,v)) for k,v in rawitems if v is not None]
    rows = [getStringFromKV(k,v) for k,v in stritems]
    return '\n'.join(rows)

def select_function(list, **where):
    def has(ea):
        d = function.tag(ea)
        for k,v in where.iteritems():
            if k not in d or (v is not None and v != d[k]):
                return False
        return True
    
    for x in list:
        if has(x):
            yield x
        continue
    return

