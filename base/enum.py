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

import sys,six,math
from internal import utils,interface as ui
import idaapi

# FIXME: complete this with more types similar to the 'structure' module.
# FIXME: normalize the documentation.

def count():
    '''Return the total number of enumerations'''
    return idaapi.get_enum_qty()

def iterate():
    '''Yield the identifier of each defined enumeration'''
    for n in xrange(idaapi.get_enum_qty()):
        yield idaapi.getn_enum(n)
    return
    
def by_name(name):
    '''Return an enum id by it's /name/'''
    res = idaapi.get_enum(name)
    if res == idaapi.BADADDR:
        raise Exception("{:s}.by_name({!r}) : Unable to locate enumeration.".format(__name__, name))
    return res
byName = by_name

def by_index(index):
    '''Return an enum id by it's /index/'''
    res = idaapi.getn_enum(index)
    if res == idaapi.BADADDR:
        raise Exception("{:s}.by_index({:x}) : Unable to locate enumeration.".format(__name__, index))
    return res
byIndex = by_index

@utils.multicase(index=six.integer_types)
def by(index):
    if index & 0xff000000 == 0xff000000:
        return index
    return by_index(index)
@utils.multicase(name=basestring)
def by(name): return by_name(n)

def keys(identifier):
    '''Given an enum id, return the names of all of it's elements.'''
    return [member.name(n) for n in member.each(identifier)]

def values(identifier):
    '''Given an enum id, return all of it's defined values'''
    return [member.value(n) for n in member.each(identifier)]

## creation/deletion
def create(name, flags=0):
    '''Create an enumeration with the specified /name/'''
    idx = count()
    res = idaapi.add_enum(idx, name, flags)
    if res == 0xffffffff:
        raise Exception("{:s}.create : Unable to create enumeration named {:s}".format(__name__, name))
    return res
def _delete(identifier):
    return idaapi.del_enum(identifier)
def delete(name):
    '''Delete an enumeration by it's /name/'''
    identifier = by_name(name)
    return _delete(identifier)
new,remove = create,delete

## setting enum options
@utils.multicase()
def name(identifier):
    '''Given an enum id, get it's /name/'''
    return idaapi.get_enum_name(identifier)
@utils.multicase(name=basestring)
def name(identifier, name):
    '''Given an enum id, set it's /name/'''
    return idaapi.set_enum_name(identifier, name)

@utils.multicase()
def comment(identifier):
    '''Given an enum id, get it's /comment/'''
    return idaapi.get_enum_cmt(identifier)
@utils.multicase(comment=basestring)
def comment(identifier, comment):
    '''Given an enum id, set it's /comment/'''
    return idaapi.set_enum_cmt(identifier, comment)

@utils.multicase()
def size(identifier):
    '''Given an enum id, get it's size'''
    res = idaapi.get_enum_width(identifier)
    return 2**(res-1) if res > 0 else 0
@utils.multicase(width=six.integer_types)
def size(identifier, width):
    '''Given an enum id, set it's size'''
    res = int(math.log(width, 2))
    return idaapi.set_enum_width(identifier, int(res)+1)

def mask(identifier):
    '''Given an enum id, return it's bitmask'''
    res = min((size(identifier), 4))    # FIXME: is uval_t/bmask_t a maximum of 32bits on ida64 too?
    if res > 0:
        return 2**(res*8)-1
    return sys.maxint*2+1

def members(identifier):
    '''Given an enum id, yield each member's name'''
    for n in member.each(identifier):
        yield member.name(n)
    return

def repr(identifier):
    '''Given an enum id, return a representation of it suitable for human consumption'''
    w = size(identifier)*2
    result = [(member.name(n),member.value(n),member.bmask(n),member.comment(n)) for n in member.each(identifier)]
    aligned = max((len(n) for n,_,_,_ in result))
    return "<type 'enum'> {:x}\n".format(identifier) + '\n'.join((' {:<{align}s} : {:0{width}x}'.format(name,value,width=w,align=aligned)+((' # '+comment) if comment else '') for name,value,bmask,comment in result))

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

        for n in enum.member.each(e):
            print enum.member.name(n)
            print enum.member.value(n)
            print enum.member.comment(n)
    '''

    @staticmethod
    def parent(identifier):
        '''Given a member id, return the enum id that is associated with it'''
        return idaapi.get_enum_member_enum(identifier)

    ## lifetime
    @classmethod
    def add(cls, enum, name, value, **kwds):
        '''Given a valid enum id, add the specified /name/ and /value/ to it'''
        bmask = kwds.get('mask', -1&mask(enum))
        res = idaapi.add_enum_member(enum, name, value, bmask)
        if res in (idaapi.ENUM_MEMBER_ERROR_NAME, idaapi.ENUM_MEMBER_ERROR_VALUE, idaapi.ENUM_MEMBER_ERROR_ENUM, idaapi.ENUM_MEMBER_ERROR_MASK, idaapi.ENUM_MEMBER_ERROR_ILLV):
            raise Exception("{:s}.member.add({:x}, {!r}, {!r}, {!r}) : Unable to add member to enumeration.".format(__name__, enum, name, value, kwds))
        return cls.byValue(enum, value)
    new = create = add

    @classmethod
    def _remove(cls, identifier):
        '''Given a member id, remove it from it's enumeraiton'''
        value = cls.value(identifier)
        # XXX: is a serial of 0 valid?
        res = idaapi.del_enum_member(cls.parent(identifier), value, 0, -1&cls.bmask(identifier))
        if not res:
            raise Exception("{:s}.member._remove({:x}) : Unable to remove member from enumeration.".format(__name__, identifier))
        return res
    _delete = _destroy = _remove

    @classmethod
    def remove(cls, enum, name):
        '''Given an enum id, remove it's member called /name/'''
        identifier = cls.by_namd(enum, name)
        return cls._remove(identifier)
    delete = destroy = remove
    
    @staticmethod
    def _each(enum):
        bmask = -1&mask(enum)
        res = idaapi.get_first_enum_member(enum, bmask)
        yield res
        while res != idaapi.get_last_enum_member(enum, bmask):
            res = idaapi.get_next_enum_member(enum, res, bmask)
            yield res
        return

    @classmethod
    def each(cls, enum):
        '''Given an enum id, yield each id of it's members'''
        bmask = -1&mask(enum)
        for v in cls._each(enum):
            res,_ = idaapi.get_first_serial_enum_member(enum, v, bmask)
            # XXX: what does get_next_serial_enum_member and the rest do?
            yield res
        return

    ## searching
    @staticmethod
    def by_value(enum, value):
        '''Given an enum id, return the member id with the specified /value/'''
        bmask = -1&mask(enum)
        res,_ = idaapi.get_first_serial_enum_member(enum, value, bmask)
        return res
    byValue = by_value

    @classmethod
    def by_name(cls, enum, name):
        '''Given an enum id, return the member id of /name/'''
        for identifier in cls.each(enum):
            if name == cls.name(identifier):
                return identifier
            continue
        return
    byName = by_name

    ## properties
    @utils.multicase()
    @staticmethod
    def name(identifier):
        '''Given a member id, fetch it's /name/'''
        return idaapi.get_enum_member_name(identifier)
    @utils.multicase(name=basestring)
    @staticmethod
    def name(identifier, name):
        '''Given a member id, set it's /name/'''
        return idaapi.set_enum_member_name(identifier, name)

    @classmethod
    def rename(cls, enum, name, newname):
        '''Given an enumeration id, rename one of it's members from /name/ to /newname/'''
        identifier = member.by_name(enum, name)
        return cls.name(identifier, newname)

    @utils.multicase()
    @staticmethod
    def comment(identifier, **kwds):
        '''Given a member id, fetch it's /comment/'''
        return idaapi.get_enum_member_cmt(identifier, kwds.get('repeatable', 1))
    @utils.multicase(comment=basestring)
    @staticmethod
    def comment(identifier, comment, **kwds):
        '''Given a member id, set it's /comment/'''
        return idaapi.set_enum_member_cmt(identifier, comment, kwds.get('repeatable', 1))

    @utils.multicase()
    @staticmethod
    def value(identifier):
        return idaapi.get_enum_member_value(identifier)
    @utils.multicase()
    @staticmethod
    def value(identifier, value, **kwds):
        '''Given a member id, fetch/set it's /value/'''
        #bmask = kwds.get('mask', -1 & mask(enum))
        bmask = kwds.get('mask', -1 & mask(identifier))
        return idaapi.set_enum_member_value(identifier, value, bmask)

    @staticmethod
    def serial(identifier):
        '''Given a member id, return it's serial'''
        return idaapi.get_enum_member_serial(identifier)

    @staticmethod
    def bmask(identifier):
        '''Given a member id, return it's bmask'''
        return idaapi.get_enum_member_bmask(identifier)
