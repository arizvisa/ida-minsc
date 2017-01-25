'''
enum-context
generic tools for working with enumerations

Examples:
e = enum.create("example_enum")
e = enum.byName("example_enum")

print enum.name(e), enum.comment(e)
print enum.size(e), enum.mask(e)

for e in enum.iterate():
    print enum.keys(e),enum.values(e)
    print enum.repr(e)

enum.delete("example_enum")
'''

import __builtin__
import sys,six,math
import functools,itertools,operator
import internal,fnmatch,re
from internal import utils,interface as ui
import idaapi

# FIXME: complete this with more types similar to the 'structure' module.
# FIXME: normalize the documentation.

def count():
    '''Return the total number of enumerations in the database.'''
    return idaapi.get_enum_qty()

def by_name(name):
    '''Return an enum id with the specified ``name``.'''
    res = idaapi.get_enum(name)
    if res == idaapi.BADADDR:
        raise LookupError("{:s}.by_name({!r}) : Unable to locate enumeration.".format(__name__, name))
    return res
byName = utils.alias(by_name)

def by_index(index):
    '''Return an enum id at the specified ``index``.'''
    res = idaapi.getn_enum(index)
    if res == idaapi.BADADDR:
        raise LookupError("{:s}.by_index({:x}) : Unable to locate enumeration.".format(__name__, index))
    return res
byIndex = utils.alias(by_index)

@utils.multicase(index=six.integer_types)
def by(index):
    bits = int(math.ceil(math.log(idaapi.BADADDR)/math.log(2.0)))
    highbyte = 0xff << (bits-8)
    if index & highbyte == highbyte:
        return index
    return by_index(index)
@utils.multicase(name=basestring)
def by(name):
    return by_name(n)

def keys(id):
    '''Return the names of all of the elements of the enumeration ``id``.'''
    return [member.name(n) for n in member.iterate(id)]

def values(id):
    '''Return the values of all of the elements of the enumeration ``id``.'''
    return [member.value(n) for n in member.iterate(id)]

## creation/deletion
def create(name, flags=0):
    '''Create an enumeration with the specified ``name``.'''
    idx = count()
    res = idaapi.add_enum(idx, name, flags)
    if res == idaapi.BADADDR:
        raise Exception("{:s}.create : Unable to create enumeration named {:s}".format(__name__, name))
    return res

@utils.multicase(index=six.integer_types)
def delete(index):
    id = by_index(id)
    return idaapi.del_enum(id)

@utils.multicase(name=basestring)
def delete(name):
    '''Delete the enumeration with the specified ``name``.'''
    res = by_name(name)
    return delete(res)
new,remove = utils.alias(create),utils.alias(delete)

## setting enum options
@utils.multicase()
def name(enum):
    '''Return the name of the enumeration identified by ``id``.'''
    id = by(enum)
    return idaapi.get_enum_name(id)
@utils.multicase(name=basestring)
def name(enum, name):
    '''Rename the enumeration identified by ``id`` to ``name``.'''
    id = by(enum)
    return idaapi.set_enum_name(id, name)

@utils.multicase()
def comment(enum, **repeatable):
    """Return the comment for the enumeration identified by ``id``.
    If the bool ``repeatable`` is specified, then return the repeatable comment.
    """
    id = by(enum)
    return idaapi.get_enum_cmt(id, repeatable.get('repeatable', True))
@utils.multicase(comment=basestring)
def comment(enum, comment, **repeatable):
    """Set the comment for the enumeration identified by ``id`` to ``cmt``.
    If the bool ``repeatable`` is specified, then modify the repeatable comment.
    """
    id = by(enum)
    return idaapi.set_enum_cmt(id, comment, repeatable.get('repeatable', True))

@utils.multicase()
def size(enum):
    '''Return the size of the enumeration identified by ``id``.'''
    id = by(enum)
    res = idaapi.get_enum_width(id)
    return 2**(res-1) if res > 0 else 0
@utils.multicase(width=six.integer_types)
def size(enum, width):
    '''Set the size of the enumeration identified by ``id`` to ``width``.'''
    id = by(enum)
    res = int(math.log(width, 2))
    return idaapi.set_enum_width(id, int(res)+1)

def mask(enum):
    '''Return the bitmask for the enumeration identified by ``id``.'''
    id = by(enum)
    res = min((size(id), 4))    # FIXME: is uval_t/bmask_t a maximum of 32bits on ida64 too?
    if res > 0:
        return 2**(res*8)-1
    return sys.maxint*2+1

def members(enum):
    '''Return the name of each member from the enumeration identified by ``id``.'''
    id = by(enum)
    for n in member.iterate(id):
        yield member.name(n)
    return

def repr(enum):
    '''Return a printable summary of the enumeration identified by ``id``.'''
    id = by(enum)
    w = size(id)*2
    result = [(member.name(n),member.value(n),member.mask(n),member.comment(n)) for n in member.iterate(id)]
    aligned = max((len(n) for n,_,_,_ in result))
    return "<type 'enum'> {:x}\n".format(id) + '\n'.join((' {:<{align}s} : {:0{width}x}'.format(name,value,width=w,align=aligned)+((' # '+comment) if comment else '') for name,value,bmask,comment in result))

__matcher__ = utils.matcher()
__matcher__.attribute('index', idaapi.get_enum_idx)
__matcher__.boolean('regex', re.search, idaapi.get_enum_name)
__matcher__.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), idaapi.get_enum_name)
__matcher__.boolean('name', operator.eq, idaapi.get_enum_name)
__matcher__.attribute('id')
__matcher__.attribute('identifier')
__matcher__.predicate('pred')
__matcher__.predicate('predicate')

def iterate(**type):
    '''Yield the id of each enumeration within the database.'''
    if not type: type = {'predicate':lambda n: True}
    res = __builtin__.range(idaapi.get_enum_qty())
    for k,v in type.iteritems():
        res = __builtin__.list(__matcher__.match(k, v, res))
    for n in res: yield n

@utils.multicase(string=basestring)
def list(string):
    '''List any enumerations that match the glob in `string`.'''
    return list(like=string)
@utils.multicase()
def list(**type):
    """List all the enumerations within the database.

    Search type can be identified by providing a named argument.
    like = glob match
    regex = regular expression
    index = particular index
    identifier = particular id number
    pred = function predicate
    """
    res = __builtin__.list(iterate(**type))

    # FIXME: this is all fucked up
    size = utils.compose(idaapi.get_enum_width, lambda n:2**(n-1) if n > 0 else 0)
    maxindex = max(__builtin__.map(idaapi.get_enum_idx, res))
    maxname = max(__builtin__.map(utils.compose(idaapi.get_enum_name, len), res))
    maxsize = max(__builtin__.map(size, res))
    cindex = math.ceil(math.log(maxindex)/math.log(10))
    csize = math.ceil(math.log(maxsize or 1)/math.log(16))

    for n in res:
        print('[{:{:d}d}] {:>{:d}s} +0x{:<{:d}x} ({:d} members){:s}'.format(idaapi.get_enum_idx(n), int(cindex), idaapi.get_enum_name(n), maxname, size(n), int(csize), len(__builtin__.list(members(n))), ' // {:s}'.format(comment(n)) if comment(n) else ''))
    return

@utils.multicase(string=basestring)
def search(string):
    '''Search through all the enumerations using globbing.'''
    return search(like=string)
@utils.multicase()
def search(**type):
    """Search through all the enumerations within the database and return the first result.

    like = glob match
    regex = regular expression
    index = particular index
    identifier or id = internal id number
    """
    searchstring = ', '.join('{:s}={!r}'.format(k,v) for k,v in type.iteritems())

    res = __builtin__.list(iterate(**type))
    if len(res) > 1:
        map(logging.info, (('[{:d}] {:s}'.format(idaapi.get_enum_idx(n), idaapi.get_enum_name(n))) for i,n in enumerate(res)))
        logging.warn('{:s}.search({:s}) : Found {:d} matching results, returning the first one.'.format(__name__, searchstring, len(res)))

    res = next(iter(res), None)
    if res is None:
        raise LookupError('{:s}.search({:s}) : Found 0 matching results.'.format(__name__, searchstring))
    return res

## members
class member(object):
    '''This class allows one to interact with the members of a defined enumeration.

    Examples:
        e = enum.byName('example_enumeration')
        print enum.repr(e)

        enum.member.rename(e, 'oldname', 'newname')

        n = enum.member.add(e, 'name', 0x1000)
        enum.member.remove(n)

        n = enum.member.byName(e, 'name')
        n = enum.member.byValue(e, 0x1000)

        enum.member.name(n, 'somename')
        enum.member.value(n, 0x100)
        enum.member.comment(n, 'This is an test value')

        for n in enum.member.iterate(e):
            print enum.member.name(n)
            print enum.member.value(n)
            print enum.member.comment(n)
    '''

    @staticmethod
    def parent(mid):
        '''Given a member id, return the enum id that is associated with it'''
        return idaapi.get_enum_member_enum(mid)

    ## lifetime
    @classmethod
    def add(cls, enum, name, value, **bitmask):
        """Add an enumeration member ``name`` with the specified ``value`` to the enumeration identified by ``id``.
        If the int, mask, is specified then used it as the bitmask for the enumeration.
        """
        id = by(enum)
        bmask = bitmask.get('bitmask', -1&mask(id))
        res = idaapi.add_enum_member(id, name, value, bmask)
        if res in (idaapi.ENUM_MEMBER_ERROR_NAME, idaapi.ENUM_MEMBER_ERROR_VALUE, idaapi.ENUM_MEMBER_ERROR_ENUM, idaapi.ENUM_MEMBER_ERROR_MASK, idaapi.ENUM_MEMBER_ERROR_ILLV):
            raise Exception("{:s}.member.add({:x}, {!r}, {!r}, {!r}) : Unable to add member to enumeration.".format(__name__, id, name, value, kwds))
        return cls.by_value(id, value)
    new = create = utils.alias(add)

    @utils.multicase(mid=six.integer_types)
    @classmethod
    def remove(cls, mid):
        '''Remove the enumeration member with the given ``mid``.'''
        value = cls.value(mid)
        # XXX: is a serial of 0 valid?
        res = idaapi.del_enum_member(cls.parent(mid), value, 0, -1&cls.mask(mid))
        if not res:
            raise LookupError("{:s}.member._remove({:x}) : Unable to remove member from enumeration.".format(__name__, mid))
        return res
    @utils.multicase()
    @classmethod
    def remove(cls, enum, member):
        '''Remove the enumeration member ``name`` from the enumeration with the given ``id``.'''
        id = by(enum)
        mid = cls.by(id, member)
        return cls.remove(mid)
    delete = destroy = utils.alias(remove)

    @staticmethod
    def __iterate(id):
        bmask = -1&mask(id)
        res = idaapi.get_first_enum_member(id, bmask)
        yield res
        while res != idaapi.get_last_enum_member(id, bmask):
            res = idaapi.get_next_enum_member(id, res, bmask)
            yield res
        return

    @classmethod
    def iterate(cls, enum):
        '''Given an enum id, yield each id of it's members'''
        id = by(enum)
        bmask = -1&mask(id)
        for v in cls.__iterate(id):
            res,_ = idaapi.get_first_serial_enum_member(id, v, bmask)
            # XXX: what does get_next_serial_enum_member and the rest do?
            yield res
        return

    ## searching
    @staticmethod
    def by_index(enum, index):
        # FIXME
        pass

    @staticmethod
    def by_identifer(enum, id):
        # FIXME
        pass

    @staticmethod
    def by_value(enum, value):
        '''Given an enum id, return the member id with the specified /value/'''
        id = by(enum)
        bmask = -1&mask(id)
        res,_ = idaapi.get_first_serial_enum_member(id, value, bmask)
        return res
    byValue = utils.alias(by_value)

    @classmethod
    def by_name(cls, enum, name):
        '''Given an enum id, return the member id of /name/'''
        id = by(enum)
        for mid in cls.iterate(id):
            if name == cls.name(mid):
                return mid
            continue
        return
    byName = utils.alias(by_name)

    @utils.multicase(member=six.integer_types)
    @classmethod
    def by(cls, enum, member):
        # FIXME: determine if it's a value, an index, or an id
        return cls.by_value(enum, member)
    @utils.multicase(member=basestring)
    @classmethod
    def by(cls, enum, member):
        return cls.by_name(enum, member)

    ## properties
    @utils.multicase()
    @staticmethod
    def name(mid):
        '''Given a member id, fetch it's /name/'''
        return idaapi.get_enum_member_name(mid)
    @utils.multicase(name=basestring)
    @staticmethod
    def name(mid, name):
        '''Given a member id, set it's /name/'''
        return idaapi.set_enum_member_name(mid, name)

    @classmethod
    def rename(cls, id, name, newname):
        '''Given an enumeration id, rename one of it's members from /name/ to /newname/'''
        res = member.by_name(id, name)
        return cls.name(res, newname)

    @utils.multicase()
    @staticmethod
    def comment(mid, **repeatable):
        '''Given a member id, fetch it's /comment/'''
        return idaapi.get_enum_member_cmt(mid, repeatable.get('repeatable', True))
    @utils.multicase(comment=basestring)
    @staticmethod
    def comment(mid, comment, **repeatable):
        '''Given a member id, set it's /comment/'''
        return idaapi.set_enum_member_cmt(mid, comment, kwds.get('repeatable', True))

    @utils.multicase()
    @staticmethod
    def value(mid):
        return idaapi.get_enum_member_value(mid)
    @utils.multicase()
    @staticmethod
    def value(mid, value, **bitmask):
        '''Given a member id, fetch/set it's /value/'''
        # FIXME: is this right
        id = cls.parent(mid)
        #bmask = bitmask.get('bitmask', -1 & mask(id))
        bmask = bitmask.get('bitmask', -1 & cls.mask(mid))
        return idaapi.set_enum_member_value(mid, value, bmask)

    @staticmethod
    def serial(mid):
        '''Given a member id, return it's serial'''
        return idaapi.get_enum_member_serial(mid)

    @staticmethod
    def mask(mid):
        '''Given a member id, return it's bmask'''
        return idaapi.get_enum_member_bmask(mid)
