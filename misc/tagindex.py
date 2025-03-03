"""
Tagindex module (internal)

This module contains the tools that are needed to maintain the indices used by
the tagging component for the plugin. The module contains numerous "schemas"
which represent the different types of tags that are available. Each definition
of these schemas tracks their corresponding tags via their name and a reference
count in order to detect when a tag is not being used by whichever context the
schema is associated with.

The primary namespace that is used to track all of the tags used throughout the
database is the `tags` namespace. This namespace provides numerous utilities for
adding and removing tags, or adjusting their reference count as a singular
transaction. If an error occurs during any of these actions, the state of the
persisted data will be rolled-back to the state before the corresponding
function was called.

It is worth noting that due to a limitation of the netnode api and this module,
the maximum number of available tags that may be used inside the database is
8192. This is the result of the maximum size for an arbitrary object inside a
netnode being MAXSPECSIZE (1024) bytes, with each bit representing a single tag
that is applied to a location. Similarly, the maximum number of references that
can be tracked and counted is limited to the native integer size that is used
for a database (32-bit or 64-bit).
"""
import functools, operator, itertools, math
import abc, contextlib, collections, heapq, string, codecs
import sys, logging, fnmatch, re
logging = logging.getLogger(__name__)

import idaapi, internal, internal.netnode
from internal import interface, utils, types, exceptions, netnode

# FIXME: we should be able to store attributes for an individual tag too. this
#        way we can control tag visibility, privacy, or perhaps have support
#        for tags with arbitrarily-sized content that can be stored with a
#        direct reference to a netnode blob.

# just some maximums
MAXIMUM_SPEC_INTEGER = pow(2, math.trunc(math.log2(1 + idaapi.BADADDR))) - 1
MAXIMUM_TAG_COUNT = 8 * idaapi.MAXSPECSIZE              # 8192
MAXIMUM_SUP_INTEGER = pow(2, 8 * idaapi.MAXSPECSIZE) - 1

# ...and some useful constants.
NSUP_START = idaapi.NSUP_ORIGFMD + 0x1000

### Define the hooks that can be used by an outsider to initialize the tagindex.
def init_tagindex(*idp_modname):
    '''This function is a hook that is responsible for deploying our schemas.'''
    schemas = [tags, globals, contents, members, structure]
    for item in schemas:
        if item.exists():
            logging.info(u"{:s}.init_tagindex({!s}) : Using the already existing netnode for \"{!s}\".".format(__name__, "{!r}".format(*idp_modname) if idp_modname else '', utils.string.escape(utils.pycompat.fullname(item), '"')))
        else:
            logging.info(u"{:s}.init_tagindex({!s}) : Creating a netnode to contain the schema for \"{!s}\".".format(__name__, "{!r}".format(*idp_modname) if idp_modname else '', utils.string.escape(utils.pycompat.fullname(item), '"')))
        node = item.create()
        if not item.initialized(node) and not item.initialize(node):
            logging.warning(u"{:s}.init_tagindex({!s}) : Unable to apply the \"{!s}\" schema to netnode {:#x}.".format(__name__, "{!r}".format(*idp_modname) if idp_modname else '', utils.string.escape(utils.pycompat.fullname(item), '"'), node))
        continue
    return

def nw_init_tagindex(nw_code, is_old_database):
    '''This function is a hook that is responsible for deploying our schemas.'''
    idp_modname = idaapi.get_idp_name()
    return __init_tagindex__(idp_modname)

def destroy_tagindex(*ignored):
    '''This function will destroy the netnodes associated with all associated schemas.'''
    schemas = [tags, globals, contents, members, structure]
    logging.info(u"{:s}.destroy_tagindex({!s}) : Destroying {:d} netnode{:s} associated with the tag index.".format(__name__, ', '.join(map("{!r}".format, ignored)) if ignored else '', len(schemas), '' if len(schemas) == 1 else 's'))
    for item in schemas:
        if item.exists():
            logging.info(u"{:s}.destroy_tagindex({!s}) : Destroying the netnode containing the schema for \"{!s}\".".format(__name__, ' ,'.join(map("{!r}".format, ignored)) if ignored else '', utils.string.escape(utils.pycompat.fullname(item), '"')))
            try:
                node = item.destroy()
            except:
                logging.error(u"{:s}.destroy_tagindex({!s}) : Error trying to destroy the netnode containing the schema for \"{!s}\".".format(__name__, ' ,'.join(map("{!r}".format, ignored)) if ignored else '', utils.string.escape(utils.pycompat.fullname(item), '"')), exc_info=True)
            else:
                logging.info(u"{:s}.destroy_tagindex({!s}) : Successfully destroyed the netnode containing the schema for \"{!s}\".".format(__name__, ' ,'.join(map("{!r}".format, ignored)) if ignored else '', utils.string.escape(utils.pycompat.fullname(item), '"')))
            pass
        else:
            logging.info(u"{:s}.destroy_tagindex({!s}) : Skipping removal of the netnode for \"{!s}\" due to the netnode not existing.".format(__name__, ', '.join(map("{!r}".format, ignored)) if ignored else '', utils.string.escape(utils.pycompat.fullname(item), '"')))
        continue
    return

### Now we can define our classes for the different indices that we track.
class schema(object):
    """
    This is a base class that contains general utilities for interacting with a
    specific netnode. This abstracts the initialization and deinitialization
    process of a netnode that is specified by the "name" attribute. Thus, a
    namespace that derives itself from this definition is expected to assign a
    name themselves.
    """

    NSUP_SCHEMA_VERSION = NSUP_START + 1

    statstag = netnode.alttag
    schema = {
        (netnode.sup, statstag): {
            NSUP_SCHEMA_VERSION: 1,
        },
    }

    @classmethod
    def create(cls):
        '''Initialize the netnode for containing the current schema and return it.'''
        name = "$ {:s}".format(cls.name)
        node = netnode.get(name) if netnode.has(name) else netnode.new(name)
        cls._node = node
        return node

    @classmethod
    def exists(cls):
        '''Return whether the netnode containing the current schema exists.'''
        name = "$ {:s}".format(cls.name)
        return netnode.has(name)

    @classmethod
    def version(cls):
        '''Returns whether the schema exists and return its version if so.'''
        name = "$ {:s}".format(cls.name)
        if not netnode.has(name):
            return

        node = netnode.get(name)
        if netnode.sup.has(node, cls.NSUP_SCHEMA_VERSION, tag=cls.statstag):
            return netnode.sup.get(node, cls.NSUP_SCHEMA_VERSION, types.integer, tag=cls.statstag)
        return

    @classmethod
    def destroy(cls):
        '''Destroy the netnode containing the current schema discarding its contents entirely.'''
        name = "$ {:s}".format(cls.name)
        if not netnode.has(name):
            return True

        node = cls.node()
        return netnode.remove(node)

    @classmethod
    def node(cls):
        '''Return the netnode containing the contents defined by the schema.'''
        if not hasattr(cls, '_node'):
            raise exceptions.MissingTypeOrAttribute(u"{:s}.node() : Unable to return the netnode as it has not yet been initialized.".format('.'.join([__name__, cls.__name__])))
        res = cls._node
        return netnode.get(res)

    @classmethod
    def initialized(cls, node):
        '''Return whether the contents of the schema for the netnode `node` has already been initialized.'''
        if not netnode.has(node):
            return False

        node = netnode.get(node)
        for interface, tag in cls.schema:
            node_defaults = cls.schema[interface, tag]
            for key, value in node_defaults.items():
                if interface.has(node, key, tag=tag):
                    continue
                return False
            continue
        return True

    @classmethod
    def initialize(cls, node):
        '''Apply the defaults from the contents of the schema attribute to the netnode `node`.'''
        results, node = [], netnode.get(node)
        for interface, tag in cls.schema:
            node_defaults = cls.schema[interface, tag]

            # iterate through all of the defaults and assign them using the
            # given interface unless the value being processed already exists.
            for key, value in node_defaults.items():
                if interface.has(node, key, tag=tag):
                    continue

                # now we can set the value and preserve its result.
                ok = interface.set(node, key, value, tag=tag)
                results.append((interface, tag, ok, key, value))
            continue

        # if everything was successful, then return success.
        if all(ok for _, _, ok, _, _ in results):
            return True

        # otherwise, we'll need to complain about it and roll it all back.
        for interface, tag, ok, key, value in results:
            if ok:
                continue

            key_description = "{:#x}".format(key) if isinstance(key, types.integer) else "{!r}".format(key)
            value_description = "{:#x}".format(value) if isinstance(value, types.integer) else "{!r}".format(value)
            tag_description = value if isinstance(tag, types.integer) else ord(value)
            interface_name = utils.pycompat.fullname(interface)
            logging.warning(u"{:s}.initialize_schema({:#x}) : Unable to assign default value ({!s}) to the key {!s} for tag {:#x} with {:s}.".format('.'.join([__name__, cls.__name__]), node, value_description, key_description, tag_description, "`{:s}`".format(interface_name)))

        # go through everything that was set and attempt to remove them one-by-one.
        for interface, tag, ok, key, _ in results:
            if not ok:
                continue

            ok = interface.has(node, key, tag=tag) and interface.remove(node, key, tag=tag)
            if not ok:
                key_description = "{:#x}".format(key) if isinstance(key, types.integer) else "{!r}".format(key)
                tag_description = value if isinstance(tag, types.integer) else ord(value)
                interface_name = utils.pycompat.fullname(interface)
                logging.warning(u"{:s}.initialize_schema({:#x}) : Unable to roll back the key {!s} for tag {:#x} with {:s}.".format('.'.join([__name__, cls.__name__]), node, value_description, key_description, tag_description, "`{:s}`".format(interface_name)))
            continue
        return False

    @classmethod
    def erase_schema(cls):
        '''Clear the values using the schema for the corresponding netnode.'''
        results, node = [], cls.node()
        for interface, tag in cls.schema:
            for key in interface.fiter(node, tag=tag):
                ok = interface.remove(node, key, tag=tag)
                results.append([interface, tag, ok, key])
            continue

        # if we succeeded removing everything, then we're good to go.
        if all(ok for _, _, ok, _ in results):
            return True

        # otherwise, log what we failed at removing.
        for interface, tag, ok, key in results:
            if ok:
                continue

            fail = interface, tag, False
            keys = {packed[-1:][0] for packed in results if packed[:-1] == fail}
            tag_description = value if isinstance(tag, types.integer) else ord(value)
            logging.debug(u"{:s}.erase({:#x}) : Unable to erase {:d} key{:s} for tag {:#x} with {:s}.".format('.'.join([__name__, cls.__name__]), node, len(keys), '' if len(keys) == 1 else 's', tag_description, "`{:s}`".format(interface_name)))

        return False

    @classmethod
    def version(cls):
        '''Return the version number for the netnode containing the current schema.'''
        node = cls.node()
        return netnode.sup.get(node, cls.NSUP_SCHEMA_VERSION, types.integer, tag=cls.statstag)

    @classmethod
    def iterate(cls, *args, **kwargs):
        '''Iterate through each key and used tags for the current schema.'''
        return cls.forward(*args, **kwargs)

    @classmethod
    @abc.abstractmethod
    def forward(cls, node, *key, **tag):
        '''Yield the key and used tags in order for the current schema from netnode `node` starting at `key` (if given).'''
        for key, integer in suptools.forward(node, *key, **tag):
            yield key, integer
        return

    @classmethod
    @abc.abstractmethod
    def backward(cls, node, *key, **tag):
        '''Yield the key and used tags in reverse for the current schema from netnode `node` starting at `key` (if given).'''
        for key, integer in suptools.backward(node, *key, **tag):
            yield key, integer
        return

class suptools(object):
    """
    This class is a wrapper around the `netnode.sup` namespace. In the
    disassembler, "supvals" can be used to associate an arbitrary type with
    an integer. In our case, we want to map an integer to another integer so
    that we can associate tags with a specific address/identifier. However,
    the "supval" api only allows you to fetch and store word-sized integers
    depending on which version of the disassembler is being used. To work
    around this limitation, we take responsibility for encoding and decoding
    the integer so that we can encode a big integer into a "supval" as its
    corresponding bytes.

    This namespace consists mostly of wrappers around the netnode api that can
    be found inside the `internal.netnode` module.
    """

    @classmethod
    def encode_integer(cls, integer):
        '''Return the specified `integer` encoded as an array of bytes.'''
        digits, divisor = [], 0x100
        while integer > 0:
            integer, digit = divmod(integer, divisor)
            digits.insert(0, digit)
        return bytearray(digits or [0])

    @classmethod
    def decode_integer(cls, bytes):
        '''Return the specified array of `bytes` decoded as an integer.'''
        iterable = iter(bytearray(bytes)) if isinstance(bytes, (b''.__class__, bytearray)) else iter(bytes or b'')
        Faggregate = lambda carry, octet: carry * 0x100 + octet
        return functools.reduce(Faggregate, iterable, 0)

    @classmethod
    def bigint(cls, node, key, *args, **kwargs):
        '''Return the integer stored at the given `key` of the netnode specified by `node`.'''
        exists = netnode.sup.has(node, key, *args, **kwargs)

        # first check to see if there is an integer stored. if not, then we can
        # just return 0 with no bits set which says that no tags are available.
        if not exists:
            return 0

        # the supval api only returns integers that are the size of a word. so,
        # to support bigints, we get it as bytes and then decode it ourselves.
        bytes = netnode.sup.get(node, key, types.bytearray, *args, **kwargs)
        return cls.decode_integer(bytes)

    @classmethod
    def setbigint(cls, node, key, integer, *args, **kwargs):
        '''Assign an `integer` to the given `key` of the netnode specified by `node`.'''
        unsigned = integer & MAXIMUM_SUP_INTEGER

        # the supval api only allows us to store word-sized integers. so, we
        # encode the integer ourselves to work around said limitation.
        if unsigned:
            unsigned_encoded = cls.encode_integer(unsigned)
            return netnode.sup.set(node, key, unsigned_encoded, *args, **kwargs)

        # if we're setting the integer to 0, then remove the supval from the
        # specified netnode. otherwise due to the nonexistence of the "supval",
        # and being asked to clear it, we can get away with doing nothing.
        elif netnode.sup.has(node, key, *args, **kwargs):
            return netnode.sup.remove(node, key, *args, **kwargs)

        return True

    @classmethod
    def forward(cls, node, *key, **tag):
        '''Yield each key and integer from `node` in order starting at the specified `key` (if given).'''
        if key:
            iterable = netnode.sup.forward(node, *itertools.chain(key[:1], [types.bytearray], key[1:], [tag.pop('tag')] if 'tag' in tag and not key[1:] else []))
        else:
            iterable = netnode.sup.fitems(node, types.bytearray, **tag)

        # now we can just decode each integer and yield it to the caller.
        for key, bytes in iterable:
            yield key, cls.decode_integer(bytes)
        return

    @classmethod
    def backward(cls, node, *key, **tag):
        '''Yield each key and integer from `node` in reverse order starting at the specified `key` (if given).'''
        if key:
            iterable = netnode.sup.backward(node, *itertools.chain(key[:1], [types.bytearray], key[1:], [tag.pop('tag')] if 'tag' in tag and not key[1:] else []))
        else:
            iterable = netnode.sup.ritems(node, types.bytearray, **tag)

        # iterate through all the bytes we got, decode an integer, and yield it.
        for key, bytes in iterable:
            yield key, cls.decode_integer(bytes)
        return

    @classmethod
    def fall(cls, node, **tag):
        '''Return a list containing all the keys and integers from the netnode specified in `node` in order.'''
        items = netnode.sup.fall(node, types.bytearray, **tag)
        return [(key, cls.decode_integer(bytes)) for key, bytes in items]

    @classmethod
    def rall(cls, node, **tag):
        '''Return a list containing all the keys and integers from the netnode specified in `node` in reverse order.'''
        items = netnode.sup.rall(node, types.bytearray, **tag)
        return [(key, cls.decode_integer(bytes)) for key, bytes in items]

    @classmethod
    def range(cls, node, start, stop, **tag):
        '''Return a list of each key and integer in `node` from the key specified by `start` until the key in `stop`.'''
        Fitems = netnode.sup.fbounds if start <= stop else netnode.sup.rbounds
        items = Fitems(node, start, stop, types.bytearray, **tag)
        return [(key, cls.decode_integer(bytes)) for key, bytes in items]

class tags(schema):
    """
    This namespace is responsible for managing all of the tag names throughout
    the different tables in a database. It's job is to ensure that the tag names
    and their positions are unique, and to allow mapping between the bit
    position and the tag name itself. We also track the reference count of each
    tag used within the database. The purpose of this is to allow freeing up the
    bit position for a tag if the last instance of that tag has been removed.

    We use 3 tables inside a netnode to facilitate this. The first table is
    using a "hashval" and is responsible for mapping a tag name to its bit
    position. The second table is using a "supval" and is responsible for
    mapping a bit position back to the corresponding tag name. The last table is
    a "supval" that is responsible for tracking the reference counts for each of
    the tags in use.

    The "supval" api has a limitation when storing or fetching integers into a
    table in that the integer size is clamped to the native word size for the
    database. To work around this limitation, we use the "supval" api to store
    data up to MAXSPECSIZE in bytes and instead handle the encoding/decoding of
    the integer value ourselves. This results in restricting the maximum number
    of tags in a database to 8 * MAXSPECSIZE (8192).

    The addition of a new tag will result in finding a bit position that
    is empty, and then allocating the tag to it. Similarly, the removal of a tag
    will result in removing that specific bit and marking it as empty. This is
    facilitated by a cached integer referred to as the "usage" mask. The
    addition and removal of tags requires the stage of this mask to be
    maintained in order to avoid traversing the list of tags to find an
    available bit position.

    The reference counting table is simply used to track the number of times a
    specific tag is used. This results in an interface where the caller
    specifies whether to increment or decrement the reference count for their
    desired tag name. The allocation or deallocation of a bit position for their
    tag is then handled automatically by this namespace.
    """

    name = 'minsc.tags.index'

    statstag = schema.statstag
    NSUP_SCHEMA_VERSION = schema.NSUP_SCHEMA_VERSION
    NSUP_TAGNAME_USAGE = NSUP_START + 0x10

    ## tags
    nametag = netnode.hashtag
    indextag = netnode.suptag
    counttag = indextag + 1

    ## schema
    schema = {
        (netnode.sup, statstag): {
            NSUP_SCHEMA_VERSION: 1,
            NSUP_TAGNAME_USAGE: 0,
        },
        (netnode.hash, nametag): {},
        (netnode.sup, indextag): {},
        (netnode.alt, counttag): {},
    }

    @classmethod
    def usage(cls, cached=True):
        '''Return a mask (cached) containing the bits that are set for all of the currently available tags.'''
        node = cls.node()

        # use our wrapper to decode a bigint from NSUP_TAGNAME_USAGE.
        if cached:
            return suptools.bigint(node, cls.NSUP_TAGNAME_USAGE, tag=cls.statstag)

        # otherwise, we iterate through all of available positions and calculate
        # the resulting mask without using the cache.
        iterable = (pow(2, position) for _, position in cls.iterate())
        used = functools.reduce(operator.or_, iterable)

        # since we just calculated the usage mask, we might as well update its
        # state in the stats table. if the value is not-synchronized, then log a
        # warning complaining about the discrepancy.
        old = suptools.bigint(node, cls.NSUP_TAGNAME_USAGE, tag=cls.statstag)
        if old == used:
            return used

        # now we'll try to apply the new usage mask to the to our usage mask.
        elif not suptools.setbigint(node, cls.NSUP_TAGNAME_USAGE, used, tag=cls.statstag):
            oldbits = old.bit_count() if hasattr(old, 'bit_count') else "{:b}".format(old).count('1')
            bits = used.bit_count() if hasattr(used, 'bit_count') else "{:b}".format(used).count('1')
            logging.warning(u"{:s}.usage({!s}) : The usage mask has become desynchronized, but could not be updated from {:d} bit{:s} to {:d} bit{:s}.".format('.'.join([__name__, cls.__name__]), cached, oldbits, '' if oldbits == 1 else 's', bits, '' if bits == 1 else 's'))
        else:
            oldbits = old.bit_count() if hasattr(old, 'bit_count') else "{:b}".format(old).count('1')
            bits = used.bit_count() if hasattr(used, 'bit_count') else "{:b}".format(used).count('1')
            logging.info(u"{:s}.usage({!s}) : The usage mask has become desynchronized and has been successfully updated from {:d} bit{:s} to {:d} bit{:s}.".format('.'.join([__name__, cls.__name__]), cached, oldbits, '' if oldbits == 1 else 's', bits, '' if bits == 1 else 's'))
        return used

    @classmethod
    def setusage(cls, used):
        '''Modify the cached mask that contains the bits for all of the available tags.'''
        node = cls.node()
        return suptools.setbigint(node, cls.NSUP_TAGNAME_USAGE, used, tag=cls.statstag)

    @classmethod
    def has(cls, name):
        '''Return whether a tag with the given `name` is currently being used.'''
        node = cls.node()
        tagname = bit = name
        if isinstance(name, types.string):
            return netnode.hash.has(node, tagname, tag=cls.nametag)
        elif not isinstance(name, types.integer):
            raise exceptions.InvalidTypeOrValueError(u"{:s}.has({!s}) : Unable to use an unsupported type ({!s}) to identify the specified tag.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), name.__class__))
        return netnode.sup.has(node, bit, tag=cls.indextag)

    @classmethod
    def used(cls, position):
        '''Return whether a tag using the specified `position` is currently being used.'''
        node = cls.node()
        tagname = bit = position
        if isinstance(position, types.integer):
            return netnode.sup.has(node, position, tag=cls.indextag)
        elif not isinstance(tagname, types.string):
            raise exceptions.InvalidTypeOrValueError(u"{:s}.used({!s}) : Unable to use an unsupported type ({!s}) to identify the specified tag.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), name.__class__))
        position = netnode.hash.get(node, tagname, types.integer, tag=cls.nametag)
        return netnode.sup.has(node, position, tag=cls.indextag)

    @classmethod
    def explode(cls, integer):
        '''Return a list containing all of the bit positions in the given `integer` that are set to true.'''
        result, consumed = [], 0
        while integer > 0:
            lsb = +integer & -integer
            bit = lsb.bit_length() - 1
            result.append(consumed + bit)
            integer, _ = divmod(integer, pow(2, 1 + bit))
            consumed += 1 + bit
        return result

    @classmethod
    def names(cls, mask):
        '''Return the tag name for each bit that is set in the given `mask`.'''
        node = cls.node()
        positions = cls.explode(mask)
        filtered = (bit for bit in positions if netnode.sup.has(node, bit, tag=cls.indextag))
        iterable = (netnode.sup.get(node, bit, types.string, tag=cls.indextag) for bit in filtered)
        return {name for name in iterable}

    @classmethod
    def get(cls, name):
        '''Return the bit position and count for the tag with the specified `name`.'''
        node = cls.node()
        tagname = bit = name
        if isinstance(name, types.integer):
            tagname = netnode.sup.get(node, bit, types.string, tag=cls.indextag)

        # use the name to get the position for the tag, and then use the
        # position to get the tag's reference count so that we can return it.
        position = netnode.hash.get(node, tagname, types.integer, tag=cls.nametag)
        if netnode.alt.has(node, position, tag=cls.counttag):
            return position, netnode.alt.get(node, position, tag=cls.counttag)
        return position, 0

    @classmethod
    def next(cls):
        '''Return the next available bit position that can be used for a new tag.'''
        currently_used = cls.usage()
        inverted_mask = currently_used ^ MAXIMUM_SUP_INTEGER
        if not inverted_mask:
            count = "{:b}".format(currently_used).count('1')
            raise OverflowError(u"{:s}.next() : Unable to find an available bit position for a new tag due to the number of tags ({:d}) being at the maximum ({:d}).".format('.'.join([__name__, cls.__name__]), count, MAXIMUM_SUP_INTEGER))
        res = +inverted_mask & -inverted_mask
        free = res.bit_length() - 1
        return free

    @classmethod
    def forward(cls):
        '''Yield the tag name and position for each tag from the current netnode in order.'''
        node = cls.node()
        for tagname, position in netnode.hash.fitems(node, types.integer, tag=cls.nametag):
            yield tagname, position
        return

    @classmethod
    def backward(cls):
        '''Yield the tag name and position for each tag from the current netnode in reverse.'''
        node = cls.node()
        for tagname, position in netnode.hash.fitems(node, types.integer, tag=cls.nametag):
            yield tagname, position
        return

    @classmethod
    def check(cls):
        '''Verify that the index and name tables are synchronized and not malformed in any way.'''
        node = cls.node()

        # grab the names.
        iterable = netnode.hash.fitems(node, types.integer, tag=cls.nametag)
        names = [(tagname, position) for tagname, position in iterable]

        # grab the bit positions.
        iterable = netnode.sup.fitems(node, types.string, tag=cls.indextag)
        positions = [(position, tagname) for position, tagname in iterable]

        # check their length.
        if len(names) != len(positions):
            return False

        # check their values.
        namelookup = {position : tagname for tagname, position in names}
        positionlookup = {position : tagname for position, tagname in positions}
        return namelookup == positionlookup

    @classmethod
    def mask(cls, names):
        '''Return an integer mask composed of all the bit positions for the tags specified by `names`.'''
        plural = names if isinstance(names, types.unordered) else [names]
        positions = (cls.get(name) for name in plural)
        bits = (pow(2, position) for position, count in positions)
        return functools.reduce(operator.or_, bits, 0)

    @classmethod
    def add(cls, name, *count):
        '''Add a new tag with the specified `name` and return its bit position with current reference `count`.'''
        node, tagname = cls.node(), name
        if cls.has(name):
            raise exceptions.DuplicateNameError(u"{:s}.add({!s}{:s}) : Unable to add a tag with the specified name ({!s}) due to the name already being used.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), "{!r}".format(name)))

        # figure out the next id that we can use, and sanity check it.
        position = cls.next()
        if cls.used(position):
            raise exceptions.DuplicateNameError(u"{:s}.add({!s}{:s}) : Unable to add a tag using the determined bit position ({:d}) due to the position being used by another tag.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), ", {:d}".format(*count) if count else '', position))

        # try and assign it into both of our tables, and initialize the refcount.
        refcount = next(iter(count), 0)
        ok_name = netnode.hash.set(node, tagname, position, tag=cls.nametag)
        ok_index = netnode.sup.set(node, position, tagname, tag=cls.indextag)
        ok_count = netnode.alt.set(node, position, refcount, tag=cls.counttag)

        # if anything failed, then rewind everything that was done.
        if not(ok_name and ok_index):
            ok_name and netnode.hash.remove(node, tagname, tag=cls.nametag)
            ok_index and netnode.sup.remove(node, tagname, tag=cls.indextag)
            raise exceptions.DisassemblerError(u"{:s}.add({!s}{:s}) : Unable to add the specified tag ({!s}) for bit position {:d} to the current netnode ({:#x}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), ", {:d}".format(*count) if count else '', "{!r}".format(name), position, node))

        # now we just need to update our usage mask in the other netnode. if we
        # couldn't update the mask with the new position, then roll-back things.
        used, bit, clear = cls.usage(), pow(2, position), ~pow(2, position)
        if not cls.setusage(used | bit):
            ok_name and netnode.hash.remove(node, tagname, tag=cls.nametag)
            ok_index and netnode.sup.remove(node, tagname, tag=cls.indextag)
            bits = used.bit_count() if hasattr(used, 'bit_count') else "{:b}".format(used).count('1')
            raise exceptions.DisassemblerError(u"{:s}.add({!s}{:s}) : Unable to set the bit position ({:d}) for the specified tag ({!s}) in the current netnode ({:#x}) containing {:d} bit{:s}.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), ", {:d}".format(*count) if count else '', position, "{!r}".format(name), node, bits, '' if bits == 1 else 's'))

        # that's it. go ahead and return the bit position for the added tag.
        return position, refcount

    @classmethod
    def discard(cls, name):
        '''Remove the tag with the specified `name` and return its bit position with reference count.'''
        node = cls.node()
        tagname = bit = name
        if not cls.has(name):
            raise exceptions.MissingTagError(u"{:s}.discard({!s}) : Unable to discard a tag with the specified name ({!s}) due to the name not being used.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), "{!r}".format(name)))

        # figure out what it is that's being removed. if we were given the tag,
        # then use that to find the position. if we were given the position,
        # then use it to find the tag.
        if isinstance(name, types.string) and netnode.hash.has(node, tagname, tag=cls.nametag):
            tagname = tagname
            position = netnode.hash.get(node, tagname, types.integer, tag=cls.nametag)

        elif isinstance(name, types.integer) and netnode.sup.has(node, bit, tag=cls.indextag):
            tagname = netnode.sup.get(node, bit, types.string, tag=cls.indextag)
            position = bit

        elif not isinstance(name, (types.string, types.integer)):
            raise exceptions.InvalidTypeOrValueError(u"{:s}.discard({!s}) : Unable to discard the specified tag due to the type ({!s}) being unsupported.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), name.__class__))

        else:
            tag_description = "bit position ({:d})" if isinstance(name, types.integer) else "name ({!r})".format(name)
            raise exceptions.MissingTagError(u"{:s}.discard({!s}) : Unable to discard the tag with the specified {:s} due to it not being found.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), tag_description))

        # now use what we just snagged to get the original value, and then
        # remove it.
        old_position = netnode.hash.get(node, tagname, types.integer, tag=cls.nametag)
        old_name = netnode.sup.get(node, position, types.string, tag=cls.nametag)
        ok_name = netnode.hash.remove(node, tagname, tag=cls.nametag)
        ok_index = netnode.sup.remove(node, position, tag=cls.indextag)

        # if we weren't successful at removing any of them, then reapply the
        # ones that actually were.
        if not all([ok_name, ok_index]):
            ok_name or netnode.hash.set(node, tagname, old_position, tag=cls.nametag)
            ok_index or netnode.sup.set(node, position, old_name, tag=cls.indextag)
            raise exceptions.DisassemblerError(u"{:s}.discard({!s}) : Unable to remove the specified tag ({!s}) and bit position {:d} from the current netnode ({:#x}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), "{!r}".format(name), position, node))

        # now we need to clear the position from our usage mask
        used, bit, clear = cls.usage(), pow(2, position), ~pow(2, position)
        if not cls.setusage(used & clear):
            ok_name or netnode.hash.set(node, tagname, old_position, tag=cls.nametag)
            ok_index or netnode.sup.set(node, position, old_name, tag=cls.indextag)
            bits = used.bit_count() if hasattr(used, 'bit_count') else "{:b}".format(used).count('1')
            raise exceptions.DisassemblerError(u"{:s}.discard({!s}) : Unable to clear the bit position ({:d}) for the specified tag ({!s}) from the current netnode ({:#x}) containing {:d} bit{:s}.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), bit, "{!r}".format(name), node, bits, '' if bits == 1 else 's'))

        # return the bit position and the reference count that was culled.
        count = netnode.alt.get(node, position, tag=cls.counttag)
        if not netnode.alt.remove(node, position, tag=cls.counttag):
            logging.warning(u"{:s}.discard({!s}) : Unable to remove the reference count ({:d}) for the specified tag ({!s}) and bit position ({:d}) from the current netnode ({:#x}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), count, "{!r}".format(name), position, node))
        return old_position, count

    @classmethod
    def count(cls, name):
        '''Return the reference count for the tag with the specified `name`.'''
        node = cls.node()
        tagname = bit = name
        if isinstance(name, types.string) and netnode.hash.has(node, tagname, tag=cls.nametag):
            position = netnode.hash.get(node, tagname, types.integer, tag=cls.nametag)

        elif isinstance(name, types.integer) and netnode.sup.has(node, bit, tag=cls.indextag):
            position = bit

        elif not isinstance(name, (types.string, types.integer)):
            raise exceptions.InvalidTypeOrValueError(u"{:s}.count({!s}) : Unable to get the reference count for the specified tag due to its type ({!s}) being unsupported.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), name.__class__))

        else:
            tag_description = "bit position ({:d})" if isinstance(name, types.integer) else "name ({!r})".format(name)
            raise exceptions.MissingTagError(u"{:s}.count({!s}) : Unable to get the reference count for the tag with the specified {:s} due to it not being found.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), tag_description))

        if netnode.alt.has(node, position, tag=cls.counttag):
            return netnode.alt.get(node, position, tag=cls.counttag)
        return 0

    @classmethod
    def counts(cls):
        '''Yield the tag name and reference count for every tag in the database.'''
        node = cls.node()
        for name, position in cls.iterate():
            if not netnode.alt.has(node, position, tag=cls.counttag):
                continue
            count = netnode.alt.get(node, position, tag=cls.counttag)
            yield name, count
        return

    @classmethod
    def increment(cls, name, amount=1):
        '''Increment the reference count by `amount` for the tag with the specified `name`.'''
        node = cls.node()
        tagname = bit = name
        if isinstance(name, types.string) and netnode.hash.has(node, tagname, tag=cls.nametag):
            position = netnode.hash.get(node, tagname, types.integer, tag=cls.nametag)

        elif isinstance(name, types.integer) and netnode.sup.has(node, bit, tag=cls.indextag):
            position = bit

        # if the tag doesn't exist, then we'll need to add it to inc its ref.
        elif isinstance(name, types.string):
            position, count = cls.add(tagname)
            logging.debug(u"{:s}.increment({!s}, {:d}) : Added a new tag named \"{:s}\" in the current netnode ({:#x}) with bit position {:d}.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, utils.string.escape(name, '"'), node, position))

        elif not isinstance(name, (types.string, types.integer)):
            raise exceptions.InvalidTypeOrValueError(u"{:s}.increment({!s}, {:d}) : Unable to increment the reference count for the specified tag due to its type ({!s}) being unsupported.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, name.__class__))

        else:
            tag_description = "bit position ({:d})" if isinstance(name, types.integer) else "name ({!r})".format(name)
            raise exceptions.MissingTagError(u"{:s}.increment({!s}, {:d}) : Unable to increment the reference count for the tag with the specified {:s} due to it not being found.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, tag_description))

        # check if we already have a reference count available.
        available, count = netnode.alt.has(node, position, tag=cls.counttag), 0
        if available:
            count = netnode.alt.get(node, position, tag=cls.counttag)

        # if the reference count is already at its max, then bail.
        if not (count + amount < MAXIMUM_SPEC_INTEGER):
            size = math.log2(count + amount)
            raise OverflowError(u"{:s}.increment({!s}, {:d}) : Unable to increment the reference count for the specified tag ({!s}) due to the current count already being at its maximum number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, "{!r}".format(name), math.trunc(size)))

        # now we can just update the refcount for the tag, and return its
        # previous value.
        if not netnode.alt.set(node, position, count + amount, tag=cls.counttag):
            raise exceptions.DisassemblerError(u"{:s}.increment({!s}, {:d}) : Unable to increment the reference count ({:d}) in the current netnode ({:#x}) for the specified tag ({!s}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, count, node, "{!r}".format(name)))
        return position, count

    @classmethod
    def decrement(cls, name, amount=1):
        '''Decrement the reference count by `amount` for the tag with the specified `name`.'''
        node = cls.node()
        tagname = bit = name
        if isinstance(name, types.string) and netnode.hash.has(node, tagname, tag=cls.nametag):
            position = netnode.hash.get(node, name, types.integer, tag=cls.nametag)

        elif isinstance(name, types.integer) and netnode.sup.has(node, bit, tag=cls.indextag):
            position = bit

        elif not isinstance(name, (types.string, types.integer)):
            raise exceptions.InvalidTypeOrValueError(u"{:s}.decrement({!s}, {:d}) : Unable to decrement the reference count for the specified tag due to its type ({!s}) being unsupported.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, name.__class__))

        else:
            tag_description = "bit position ({:d})" if isinstance(name, types.integer) else "name ({!r})".format(name)
            raise exceptions.MissingTagError(u"{:s}.decrement({!s}, {:d}) : Unable to decrement the reference count for the tag with the specified {:s} due to it not being found.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, tag_description))

        # make sure that the refcount actually exists and then grab it.
        if not netnode.alt.has(node, position, tag=cls.counttag):
            name_description = "{:d}".format(name) if isinstance(name, types.integer) else "{!r}".format(name)
            raise exceptions.MissingTagError(u"{:s}.decrement({!s}, {:d}) : Unable to decrement the reference count for the specified tag ({!s}) due to it not being found.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, name_description))

        count = netnode.alt.get(node, position, tag=cls.counttag)

        # check if we're just decrementing the count, or removing the tag.
        if not(count > amount):
            bit, count = cls.discard(position)
            logging.debug(u"{:s}.decrement({!s}, {:d}) : Removed the tag with bit position {:d} from the current netnode ({:#x}) due to its reference count being {:d}.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, position, node, count - 1))
            return count

        elif not netnode.alt.set(node, position, count - amount, tag=cls.counttag):
            raise exceptions.DisassemblerError(u"{:s}.decrement({!s}, {:d}) : Unable to decrement the reference count ({:d}) in the current netnode ({:#x}) for the specified tag ({!s}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, count, node, "{!r}".format(name)))
        return position, count

    @classmethod
    @contextlib.contextmanager
    def guarded_increment(cls, name, amount=1):
        '''Increment the reference count for the tag with the specified `name` by `amount` as long as the code being guarded does not raise an exception.'''
        position, count = cls.get(name)
        try:
            yield position, count + amount
        except:
            logging.info(u"{:s}.guarded_increment({!s}, {:d}) : Rolling back the incremented reference count for tag \"{:s}\" ({:d}) back to its previous value ({:d}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, utils.string.escape(name, '"'), position, count))
            if not netnode.alt.set(cls.node(), position, count, tag=cls.counttag):
                logging.error(u"{:s}.guarded_increment({!s}, {:d}) : Unable to roll back the incremented reference count for tag \"{:s}\" ({:d}) back to its previous value ({:d}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, utils.string.escape(name, '"'), position, count))
            raise
        finally:
            pass
        return cls.increment(name, amount)

    @classmethod
    @contextlib.contextmanager
    def guarded_decrement(cls, name, amount=1):
        '''Decrement the reference count for the tag with the specified `name` as long as the code being guarded does not raise an exception.'''
        position, count = cls.get(name)
        try:
            yield position, count - amount
        except:
            logging.info(u"{:s}.guarded_decrement({!s}, {:d}) : Rolling back the decremented reference count for tag \"{:s}\" ({:d}) back to its previous value ({:d}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, utils.string.escape(name, '"'), position, count))
            if not netnode.alt.set(cls.node(), position, count, tag=cls.counttag):
                logging.error(u"{:s}.guarded_decrement({!s}, {:d}) : Unable to roll back the decremented reference count for tag \"{:s}\" ({:d}) back to its previous value ({:d}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, utils.string.escape(name, '"'), position, count))
            raise
        return cls.decrement(name, amount)

    @classmethod
    @contextlib.contextmanager
    def transactional_adjust(cls, name):
        """Return a context manager that provides a coroutine which can be used to adjust the reference count for the tag `name`.

        The returned coroutine is sent a single parameter which will be added
        to the current tag reference count. Upon success, the adjusted reference
        count will be committed to the netnode. If an exception is caught by the
        context manager, the changes from the transaction will be aborted.
        """
        node, used = cls.node(), cls.usage()
        tagname = bit = name

        # if the tag (a position or name) exists, then determine its position
        # and use it to fetch its reference count.
        if isinstance(name, types.string) and netnode.hash.has(node, tagname, tag=cls.nametag):
            position = netnode.hash.get(node, tagname, types.integer, tag=cls.nametag)
            available = netnode.alt.has(node, position, tag=cls.counttag)
            count = netnode.alt.get(node, position, tag=cls.counttag) if available else 0

        elif isinstance(name, types.integer) and netnode.sup.has(node, bit, tag=cls.indextag):
            position, tagname = bit, netnode.sup.get(node, bit, types.string, tag=cls.indextag)
            available = netnode.alt.has(node, position, tag=cls.counttag)
            count = netnode.alt.get(node, position, tag=cls.counttag) if available else 0

        # if the tag wasn't found, then add it to get the position and count.
        elif isinstance(name, types.string):
            position, count = cls.add(tagname)
            logging.debug(u"{:s}.transactional_adjust({!s}) : Added a new tag named \"{:s}\" in the current netnode ({:#x}) with bit position {:d}.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), utils.string.escape(tagname, '"'), node, position))

        # if we still couldn't find it, then either the name was a non-existing
        # bit position, or we were given an unsupported type to find the tag.
        elif not isinstance(name, (types.string, types.integer)):
            raise exceptions.InvalidTypeOrValueError(u"{:s}.transactional_adjust({!s}) : Unable to adjust the reference count for the specified tag due to its type ({!s}) being unsupported.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), name.__class__))

        else:
            tag_description = "bit position ({:d})" if isinstance(name, types.integer) else "name ({!r})".format(name)
            raise exceptions.MissingTagError(u"{:s}.transactional_adjust({!s}) : Unable to adjust the reference count for the tag with the specified {:s} due to it not being found.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), tag_description))

        # now we should have a bit position and initial reference count for the
        # tag which gives us enough to define a coroutine for adjusting it.
        def adjustment_closure(position, count):
            '''This coroutine will receive amounts that will be used to adjust the current reference `count` for the tag at the specified `position`.'''
            adjustment = 0
            try:
                while True:
                    amount = (yield position, count + adjustment)
                    if not(count + adjustment + amount < MAXIMUM_SPEC_INTEGER):
                        raise OverflowError(u"{:s}.transactional_adjust({!s}) : Unable to adjust the reference count by {:+d} for the tag \"{:s}\" due to the result being larger than the maximum value ({:#x}{:+#x}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, utils.string.escape(tagname, '"'), count, adjustment))

                    # we also check for underflow because technically if the tag
                    # was created, resulting in the reference count being 0, we
                    # should be raising an exception since it doesn't exist.
                    elif count + adjustment + amount < 0:
                        logging.info(u"{:s}.transactional_adjust({!s}) : Ignoring inability to decrement the reference count by {:+d} for the tag \"{!s}\" due to the count being smaller than the minimum value ({:#x}{:+#x}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), amount, utils.string.escape(tagname, '"'), count, adjustment))

                    adjustment += amount

            # if the generator is done, then calculate the new reference count.
            except GeneratorExit:
                if not (count + adjustment < MAXIMUM_SPEC_INTEGER):
                    raise OverflowError(u"{:s}.transactional_adjust({!s}) : Aborting the transaction to set the reference count for tag \"{:s}\" ({:#x}) to an out-of-bounds value {:#x}.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), utils.string.escape(tagname, '"'), count, count + adjustment))

                newcount = count + adjustment

            # if an exception was raised, log an error and discard our transaction.
            except:
                logging.info(u"{:s}.transactional_adjust({!s}) : Aborting the transaction to set the reference count for tag \"{:s}\" ({:d}) from its previous value ({:d}) to the new value {:d} ({:+d}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), utils.string.escape(tagname, '"'), position, count, count + adjustment, adjustment))
                raise

            # now we just need to update the reference count for the tag at the
            # selected position to its new reference count. If the count is 0 or
            # negative, then we need to discard the tag to remove it properly.
            if not(newcount > 0):
                bit, count = cls.discard(position)
                logging.debug(u"{:s}.transactional_adjust({!s}) : Removed the tag at position {:d} from the current netnode ({:#x}) due to its reference count being {:d}.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), position, node, newcount))

            elif not netnode.alt.set(node, position, newcount, tag=cls.counttag):
                raise exceptions.DisassemblerError(u"{:s}.transactional_adjust({!s}) : Unable to set the reference count for tag \"{:s}\" ({:d}) in the netnode {:#x} to its new value ({:#x}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), utils.string.escape(tagname, '"'), count, node, newcount))
            return

        # instantiate our coroutine, and return it with the bit position so that
        # it can be used to adjust the reference count.
        coroutine = adjustment_closure(position, count); next(coroutine)
        try:
            yield position, coroutine

            # close the coroutine as the user is probably done with it.
            coroutine.close()

        # if an exception was raised while exiting our coro, then we need to
        # be sure to restore the count for the position back to the original.
        # if the count was 0, then we remove the tag since we had to add it.
        except:
            logging.info(u"{:s}.transactional_adjust({!s}) : Rolling back the state of the tag \"{:s}\" ({:d}) based on its previous reference count ({:d}).".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), utils.string.escape(tagname, '"'), position, count))

            # just need to reraise if the count is nonzero (meaning the tag had
            # already been created). since we haven't written the new count yet,
            # there's nothing for us to actually restore.
            if count:
                raise

            # the reference count was 0, which meant that we added the tag. so
            # in this case, we need to undo the tag addition manually. we do
            # this to avoid discard() which can raise a potential exception.
            ok_name = netnode.hash.remove(node, tagname, tag=cls.nametag)
            ok_index = netnode.sup.remove(node, position, tag=cls.indextag)
            ok_count = netnode.alt.remove(node, position, tag=cls.counttag)
            ok_usage = cls.setusage(used)

            # if we didn't complete removal, then log an error before reraising.
            if not all([ok_name, ok_index, ok_count, ok_usage]):
                bits = used.bit_count() if hasattr(used, 'bit_count') else "{:b}".format(used).count('1')
                ok_name and logging.error(u"{:s}.transactional_adjust({!s}) : Unable to remove the recently added tag \"{:s}\" ({:d}) from netnode {:#x}.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), utils.string.escape(tagname, '"'), position, node))
                ok_index and logging.error(u"{:s}.transactional_adjust({!s}) : Unable to remove the recently added bit position {:d} ({!s}) from netnode {:#x}.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), position, "{!r}".format(tagname), node))
                ok_count and logging.error(u"{:s}.transactional_adjust({!s}) : Unable to remove the recently added reference count for tag \"{:s}\" ({:d}) from netnode {:#x}.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), utils.string.escape(tagname, '"'), position, node))
                ok_usage and logging.error(u"{:s}.transactional_adjust({!s}) : Unable to restore the usage mask from netnode {:#x} to the original {:d} tag{:s}.".format('.'.join([__name__, cls.__name__]), "{!r}".format(name), node, bits, '' if bits == 1 else 's'))

            raise
        return

    @classmethod
    def repr(cls, *pattern):
        '''Display the contents of the index containing the tag position and attribute information.'''
        Fmatch = re.compile(fnmatch.translate(*pattern), re.IGNORECASE).match if pattern else utils.fconstant(True)
        res = [(name, cls.count(position), position) for name, position in cls.iterate()]

        iterable = (u"{:d}".format(position) for _, _, position in res)
        position_width = max(map(len, iterable)) if res else 0

        iterable = (u"({:+d})".format(count) for _, count, _ in res)
        count_width = max(map(len, iterable)) if res else 1

        iterable = map(operator.itemgetter(0), res)
        name_width = max(map(len, map("{!s}".format, iterable))) if res else 0

        lines = []
        lines.append(u"Schema version: {:d}".format(cls.version()))
        lines.append(u"Usage mask (cached): {:#x}".format(cls.usage()))
        for name, count, position in res:
            mask = pow(2, position)
            message = u"{:<{:d}s} {:>{:d}s} : {:d} ({:#0x})"
            if Fmatch(name):
                lines.append(message.format("{!s}".format(name), name_width, "({:+d})".format(count), count_width, position, mask))
            continue

        if not lines:
            lines.append(u'No tags were found')
        return '\n'.join(lines)

class counted(schema):
    """
    This namespace is a wrapper around the `netnode.sup` namespace and is
    intended to be used for tracking and maintaining the tags that are being
    removed or applied. This is done by tracking the tag names associated with a
    key, storing a reference count for the tag names, and maintaining a usage
    mask for the tag names that are being used. This should allow a derived
    namespace to store an explicit mask, but also expose a integer mask to
    allow filtering the specified keys with.

    In order to accomplish this, the namespace requires the caller to define two
    tables.  The first table contains the tags being used for a given key, and
    is a "supval" table that stores big integers for the used tags. The second
    table is responsible for tracking the reference count for the tags applied
    to a given key. The second table containing the reference count is captured
    by a derived class using the `counted.hascount`, `counted.getcount`, and
    `counted.setcount` functions. This second table is used to track the current
    usage for the tags applied to a key and removing it if the reference count
    for the tag name is 0.

    The location used to store the usage mask is intended to be implemented
    using the `counted.getusage` and the `counted.setusage` functions. By
    allowing an implementor to overload the specified functions, the derived
    namespace can be customized to control (and how) the reference counts are
    stored, and to store the usage mask at a designated location while the
    original implementation is maintaining it.

    When the tag being incremented does not exist in the used tags for the
    chosen key, the reference count for the tag is created and the bit
    position for the tag is set. If decrementing the tag results in the
    reference count being 0, the bit position for the tag is removed from
    the used tags associated with the given key.
    """

    ## these next five abstract classmethods are intended to be wrapped and
    ## implemented by the derived namespace. when implementing these methods in
    ## the derived namespace, the number of parameters must be preserved. Each
    ## of them are used by the `counted.increment` and `counted.decrement`
    ## functions.

    @classmethod
    @abc.abstractmethod
    def hascount(cls, node, key, position, tag):
        '''Return whether the reference count for the tag at `position` of the given `key` in the netnode specified by `node` exists.'''
        return netnode.alt.has(node, position, tag=tag)

    @classmethod
    @abc.abstractmethod
    def getcount(cls, node, key, position, tag):
        '''Return the reference count for the tag at `position` for the given `key` from the netnode specified by `node`.'''
        if netnode.alt.has(node, position, tag=tag):
            return netnode.alt.get(node, position, tag=tag)
        return 0

    @classmethod
    @abc.abstractmethod
    def setcount(cls, node, key, position, count, tag):
        '''Set the reference count for the tag at `position` for the given `key` from the netnode specified in `node` to `count`.'''
        if count > 0:
            return netnode.alt.set(node, position, count, tag=tag)
        elif netnode.alt.has(node, position, tag=tag):
            return netnode.alt.remove(node, position, tag=tag)
        return True

    @classmethod
    @abc.abstractmethod
    def getusage(cls, node, key, tag):
        '''Return the usage mask for the given `key` in the table `tag` from the netnode specified by `node`.'''
        return suptools.bigint(node, key, tag=tag)

    @classmethod
    @abc.abstractmethod
    def setusage(cls, node, key, used, tag):
        '''Set the usage mask for the given `key` in the table `tag` from the netnode specified by `node` to the integer `used`.'''
        return suptools.setbigint(node, key, used, tag=tag)

    @classmethod
    def get(cls, node, key, tag):
        '''Return all of the tag names that associated with the given `key` in the table `tag` from the netnode specified by `node`.'''
        res = suptools.bigint(node, key, tag=tag)
        return tags.names(res)

    @classmethod
    def increment(cls, node, key, name, tag):
        '''Increment the reference count of the tag `name` by `amount` at the specified `key` in the table `tag` from the netnode `node`.'''
        position, count = tags.get(name) if tags.has(name) else tags.add(name)
        bit, clear = pow(2, position), ~pow(2, position)

        # first we get the reference count, its key usage, and overall usage.
        count = cls.getcount(node, key, position, tag)
        used = cls.getusage(node, key, tag)
        res = suptools.bigint(node, key, tag=tag)

        # if the tag already exists in the key mask, we don't need to do anything.
        if res & bit:
            return position, count

        # if the reference count is already at its maximum, then we abort.
        elif not (count + 1 < MAXIMUM_SPEC_INTEGER):
            bits = count.bit_count() if hasattr(count, 'bit_count') else "{:b}".format(count).count('1')
            raise OverflowError(u"{:s}.increment({:#x}, {:#x}, {!s}, {:#x}) : Unable to increment the reference count for the specified tag ({!s}) due to the count already being at its maximum number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, "{!r}".format(name), bits))

        # now we're ready to increment the tag count and update its usage.
        with tags.guarded_increment(name) as (position, tagcount):
            if not cls.setcount(node, key, position, count + 1, tag):
                raise exceptions.DisassemblerError(u"{:s}.increment({:#x}, {:#x}, {!s}, {:#x}) : Unable to increment the reference count ({:d}) in the current netnode ({:#x}) for the specified tag ({!s}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, count, node, "{!r}".format(name)))

            elif not(used & bit) and not cls.setusage(node, key, used | bit, tag):
                logging.info(u"{:s}.increment({:#x}, {:#x}, {!s}, {:#x}) : Rolling back the reference count at {:#x} to its previous value ({:d}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, key, count))
                if not suptools.setcount(node, key, position, count, tag):
                    logging.error(u"{:s}.increment({:#x}, {:#x}, {!s}, {:#x}) : Unable to roll back the reference count at {:#x} to its previous value ({:d}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, key, count))
                raise exceptions.DisassemblerError(u"{:s}.increment({:#x}, {:#x}, {!s}, {:#x}) : Unable to update the usage mask ({:d}) in the current netnode ({:#x}) with the specified tag ({!s}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, count, node, "{!r}".format(name)))

            # afterwards, we can update the key mask and return the new count.
            elif suptools.setbigint(node, key, res | bit, tag=tag):
                return position, 1 + count

            # if we couldn't update it, then we have to undo the reference count
            # that we wrote. if we can't, then we log an error before aborting.
            logging.info(u"{:s}.increment({:#x}, {:#x}, {!s}, {:#x}) : Rolling back the reference count at {:#x} to its previous value ({:d}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, key, count))
            if not cls.setcount(node, key, position, count, tag):
                logging.error(u"{:s}.increment({:#x}, {:#x}, {!s}, {:#x}) : Unable to roll back the reference count at ({:#x}) to its previous value ({:d}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, 1 + count, count, "{!r}".format(name), key, count))

            # we also need to restore the usage mask if we updated it.
            bits = used.bit_count() if hasattr(used, 'bit_count') else "{:b}".format(used).count('1')
            logging.info(u"{:s}.increment({:#x}, {:#x}, {!s}, {:#x}) : Rolling back the usage mask for {:#x} to its previous number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, key, count))
            if not(used & bit) and not cls.setusage(node, key, used, tag):
                logging.error(u"{:s}.increment({:#x}, {:#x}, {!s}, {:#x}) : Unable to roll back the usage mask for {:#x} to its previous number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, "{!r}".format(name), key, bits))

            raise exceptions.DisassemblerError(u"{:s}.increment({:#x}, {:#x}, {!s}, {:#x}) : Unable to increment the reference count of the specified tag ({!s}) at {:#x} from the current netnode ({:#x}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, "{!r}".format(name), key, node))
        return

    @classmethod
    def decrement(cls, node, key, name, tag):
        '''Decrement the reference count of the tag `name` by `amount` at the specified `key` in the table `tag` from the netnode `node`.'''
        if not(tags.has(name)):
            raise exceptions.MissingTagError(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Unable to decrement the reference count of the specified tag ({!s}) at {:#x} from the current netnode ({:#x}) due to the tag not being available.".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, "{!r}".format(name), key, node))

        # grab the tag position that we just checked for. we then double-check
        # that the refcount for it actually exists so we can adjust it.
        position, count = tags.get(name)
        bit, clear = pow(2, position), ~pow(2, position)

        if not cls.hascount(node, key, position, tag):
            name_description = "{:d}".format(name) if isinstance(name, types.integer) else "{!r}".format(name)
            raise exceptions.MissingTagError(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Unable to decrement the reference count for the specified tag ({!s}) due to it not being found.".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, name_description))

        # now we can grab the original values of the things we're gonna modify.
        count = cls.getcount(node, key, position, tag)
        used = cls.getusage(node, key, tag)
        res = suptools.bigint(node, key, tag=tag)

        # if the tag doesn't exist in the key mask, then don't do anything.
        if not (res & bit):
            return position, count

        # if the reference count is an invalid value, then abort here.
        elif not (count > 0):
            raise OverflowError(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Unable to decrement the reference count for the specified tag ({!s}) due to the count having an invalid value ({:-d}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, "{!r}".format(name), count))

        # now we're ready to tamper with the reference counts. if the count is
        # larger than 1, then we do a simple decrement and raise an exception if
        # we couldn't modify it.
        with tags.guarded_decrement(name) as (position, tagcount):
            if count > 1 and not cls.setcount(node, key, position, count - 1, tag):
                raise exceptions.DisassemblerError(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Unable to decrement the reference count ({:d}) in the current netnode ({:#x}) for the specified tag ({!s}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, count, node, "{!r}".format(name)))

            # if that was successful, then we can clear the tag from the
            # key, and return our newly decremented reference count.
            elif count > 1 and suptools.setbigint(node, key, res & clear, tag=tag):
                return position, count - 1

            # if the new reference count will be 0, then we need to free it. we
            # start by removing the tag from the used tags for the key.
            if not suptools.setbigint(node, key, res & clear, tag=tag):
                raise exceptions.DisassemblerError(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Unable to decrement the reference count of the specified tag ({!s}) at {:#x} from the current netnode ({:#x}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, "{!r}".format(name), key, node))

            # then we decrement the tag's reference count from 1 to 0.
            elif not cls.setcount(node, key, position, count - 1, tag):
                bits = res.bit_count() if hasattr(res, 'bit_count') else "{:b}".format(res).count('1')
                logging.info(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Rolling back the key mask at {:#x} to its previous number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, key, bits))
                if not suptools.setbigint(node, key, res, tag=tag):
                    logging.error(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Unable to roll back the key mask at {:#x} to its previous number of bits.".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, key, bits))
                raise exceptions.DisassemblerError(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Unable to decrement the reference count ({:d}) in the current netnode ({:#x}) for the specified tag ({!s}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, count, node, "{!r}".format(name)))

            # now we can adjust the usage mask if it was necessary. if we were
            # successful, then we can return our new reference count (0).
            elif used & bit and cls.setusage(node, key, used & clear, tag):
                return position, count - 1

            # if the used integer already had its values cleared, then there is
            # an index discrepancy. we leave successfully, but log a complaint.
            elif not(used & bit):
                logging.warning(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Ignoring inconsistency with the used tags at {:#x} for the specified tag ({!s}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, key, "{!r}".format(name)))
                return position, count - 1

            # otherwise, we roll back the key mask that was first updated.
            bits = res.bit_count() if hasattr(res, 'bit_count') else "{:b}".format(res).count('1')
            logging.info(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Rolling back the key mask at {:#x} to its previous number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, key, bits))
            if not suptools.setbigint(node, key, res, tag=tag):
                logging.error(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Unable to roll back the key mask at {:#x} to its previous number of bits.".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, key, bits))

            # and the reference count that was updated afterwards.
            logging.info(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Rolling back the reference count at {:#x} to its previous value ({:d}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, key, count))
            if not cls.setcount(node, key, position, count, tag):
                logging.error(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Unable to roll back the reference count ({:d} to {:d}) for the given tag ({!s}) at the specified key ({:#x}) in the current netnode ({:#x}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, count - 1, count, "{!r}".format(name), key, node))

            # and restore the used tags integer if it was also updated.
            bits = used.bit_count() if hasattr(used, 'bit_count') else "{:b}".format(used).count('1')
            logging.info(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Rolling back the used tags for {:#x} to its previous number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, key, bits))
            if used & bit and not cls.setusage(node, key, used & clear, tag):
                logging.error(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Unable to roll back the used tags for {:#x} to its previous number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, key, bits))

            raise exceptions.DisassemblerError(u"{:s}.decrement({:#x}, {:#x}, {!s}, {:#x}) : Unable to decrement the reference count of the specified tag ({!s}) for key {:#x} in the current netnode ({:#x}).".format('.'.join([__name__, cls.__name__]), node, key, "{!r}".format(name), tag, "{!r}".format(name), key, node))
        return

    @classmethod
    def forward(cls, node, *key, **tag):
        '''Yield the address and mask for each tag starting in order at `key` (if given).'''
        for key, integer in suptools.forward(node, *key, **tag):
            yield key, integer
        return

    @classmethod
    def backward(cls, node, *key, **tag):
        '''Yield the address and mask for each tag starting in reverse at `key` (if given).'''
        for key, integer in suptools.backward(node, *key, **tag):
            yield key, integer
        return

    @classmethod
    def range(cls, node, start, stop, tag):
        '''Return a list of each key and mask from the key `start` to `stop`.'''
        items = suptools.range(node, start, stop, tag=tag)
        return [(key, integer) for key, integer in items]

class globals(counted):
    """
    This namespace is used to update the tag state for all the globals in
    the database. Each global tag contains a target address and the tag names
    associated with it. We track this by storing a binary mask where each digit
    represents the tag name that has been applied to the address.

    For persisting information about globals, a "supval" table is used in the
    defined netnode. The "supval" api only allows storage of integers that are
    natively sized according to the disassembler version. We work around this by
    encoding the integer ourselves in order to use all the bytes that are
    available (MAXSPECSIZE) within a "supval".

    This depends on the `tags` namespace to perform all the conversion and do
    the reference counting.
    """
    name = 'minsc.tags.globals'

    statstag = schema.statstag
    NSUP_SCHEMA_VERSION = schema.NSUP_SCHEMA_VERSION
    NSUP_TAGNAME_USAGE = NSUP_START + 0x10

    ## tags
    addresstag = netnode.suptag
    counttag = addresstag + 1

    ## schema
    schema = {
        (netnode.sup, statstag): {
            NSUP_SCHEMA_VERSION: 1,
            NSUP_TAGNAME_USAGE: 0,
        },
        (netnode.sup, addresstag): {},
        (netnode.alt, counttag): {},
    }

    @classmethod
    def get(cls, ea):
        '''Return all of the tags that are currently associated with the global address `ea`.'''
        node = cls.node()
        res = suptools.bigint(node, idaapi.ea2node(ea), tag=cls.addresstag)
        return tags.names(res)

    @classmethod
    def getusage(cls, node, key, *tag, **kwargs):
        '''Return the usage mask containing tags used by the globals.'''
        node = cls.node()
        return super(globals, cls).getusage(node, cls.NSUP_TAGNAME_USAGE, cls.statstag)

    @classmethod
    def usage(cls):
        '''Return the usage mask for all the tags applied to the globals in the database.'''
        node = cls.node()
        return super(globals, cls).getusage(node, cls.NSUP_TAGNAME_USAGE, cls.statstag)

    @classmethod
    def setusage(cls, node, key, used, *tag, **kwargs):
        '''Set the usage mask for the function `func` to the integer in `used`.'''
        node = cls.node()
        return super(globals, cls).setusage(node, cls.NSUP_TAGNAME_USAGE, used, cls.statstag)

    @classmethod
    def hascount(cls, node, key, position, *tag, **kwargs):
        '''Return whether the reference count at the specified `key` exists for the tag at `position` of the netnode specified by `node`.'''
        return super(globals, cls).hascount(node, key, position, cls.counttag)

    @classmethod
    def getcount(cls, node, key, position, *tag, **kwargs):
        '''Return the reference count at the specified `key` for the tag at `position` of the netnode specified by `node`.'''
        return super(globals, cls).getcount(node, key, position, cls.counttag)

    @classmethod
    def setcount(cls, node, key, position, count, *tag, **kwargs):
        '''Set the reference count at the specified `key` for the tag at `position` of the netnode specified by `node` to `count`.'''
        return super(globals, cls).setcount(node, key, position, count, cls.counttag)

    @classmethod
    def increment(cls, ea, name):
        '''Increment the reference count for the tag with the specified `name` at the global address `ea`.'''
        node = cls.node()
        position, count = tags.get(name) if tags.has(name) else tags.add(name)
        return super(cls, globals).increment(node, idaapi.ea2node(ea), position, tag=cls.addresstag)

    @classmethod
    def decrement(cls, ea, name):
        '''Decrement the reference count for the tag with the specified `name` at the global address `ea`.'''
        node = cls.node()
        if not(tags.has(name)):
            raise exceptions.MissingTagError(u"{:s}.decrement({:#x}, {!s}) : Unable to decrement the reference count of the specified tag ({!s}) due to the tag not being available.".format('.'.join([__name__, cls.__name__]), ea, "{!r}".format(name), "{!r}".format(name)))
        position, count = tags.get(name)
        return super(cls, globals).decrement(node, idaapi.ea2node(ea), position, tag=cls.addresstag)

    @classmethod
    def forward(cls, *ea):
        '''Yield the address and mask for each tag starting from the global address `ea` (if given).'''
        node = cls.node()
        for key, integer in super(globals, cls).forward(node, *map(idaapi.ea2node,ea), tag=cls.addresstag):
            yield idaapi.node2ea(key), integer
        return

    @classmethod
    def backward(cls, *ea):
        '''Yield the address and mask for each tag in reverse from the global address `ea` (if given).'''
        node = cls.node()
        for key, integer in super(globals, cls).backward(node, *map(idaapi.ea2node, ea), tag=cls.addresstag):
            yield idaapi.node2ea(key), integer
        return

    @classmethod
    def range(cls, start, stop):
        '''Return a list containing the global addresses and masks from the address `start` to `stop`.'''
        node = cls.node()
        items = suptools.range(node, idaapi.ea2node(start), idaapi.ea2node(stop), tag=cls.addresstag)
        return [(idaapi.node2ea(key), integer) for key, integer in items]

    @classmethod
    def select(cls, addresses):
        '''Yield the address and mask for each of the specified global `addresses`.'''
        node = cls.node()
        iterable = addresses if isinstance(addresses, types.unordered) else [addresses]
        for key in map(idaapi.ea2node, iterable):
            mask = suptools.bigint(node, key, tag=cls.addresstag)
            yield idaapi.node2ea(key), mask
        return

    @classmethod
    def erase(cls, start, *stop):
        '''Remove all the global addresses and masks from the address `start` to `stop`.'''
        node = cls.node()
        if stop:
            parameters = map(idaapi.ea2node, itertools.chain([start], stop))
            items = suptools.range(node, *parameters, tag=cls.addresstag)

        else:
            integer = suptools.bigint(node, idaapi.ea2node(start), tag=cls.addresstag)
            items = [(idaapi.ea2node(start), integer)]

        count = 0
        for key, integer in items:
            ea, names = idaapi.node2ea(key), tags.names(integer)
            [cls.decrement(idaapi.ea2node(ea), name) for name in names]
            count += len(names)
        return count

    @classmethod
    def repr(cls, *pattern):
        '''Display the contents of the index containing information about the globals from the database.'''
        Fmatch = re.compile(fnmatch.translate(*pattern), re.IGNORECASE).match if pattern else utils.fconstant(True)
        used = cls.getusage(cls.node(), cls.NSUP_TAGNAME_USAGE, cls.statstag)
        names = tags.names(used)
        items = [(ea, integer) for ea, integer in cls.iterate() if Fmatch("{:#x}".format(ea))]

        iterable = (','.join(map("{:d}".format, tags.explode(integer))) for ea, integer in items)
        positions_width = max(map(len, iterable)) if items else 0

        lines = []
        lines.append(u"Schema version: {:d}".format(cls.version()))
        lines.append(u"Used tags (mask): {:#x}".format(used))
        lines.append(u"Used tags (name): ({:d}) {!s}".format(len(names), ', '.join(map(repr, names))))
        lines.append(u'Globals with tags:')
        for ea, integer in items:
            if not Fmatch("{:#x}".format(ea)): continue
            names = tags.names(integer)
            exploded = ','.join(map("{:d}".format, tags.explode(integer)))
            lines.append("{:#x}: {:<{:d}s} : {!s}".format(ea, exploded, positions_width, names))
        return '\n'.join(lines)

class contents(counted):
    """
    This namespace is used to update the tag state for any tags applied to an
    address that belongs to a function. We don't store any information about the
    function, instead opting to keep all contents isolated within its own table.
    This requires a caller to explicitly filter the results for whichever
    function they want them for. The contents information stores two things. The
    first being the address it is at. The second being the tags that have been
    applied to that address. Both are stored as an integer for reasons of
    algorithmic performance.

    For persisting the information about each content address, a "supval" table
    is used in the defined netnode. Due to the "supval" api only allowing the
    storage of integers that are sized according to the database, we instead
    handle the encoding and decoding of integers ourselves. This allows us to
    use all of the bytes (MAXSPECSIZE) available in a "supval" to store the tag
    information.

    We also maintain another "supval" table to track the contents tags
    associated with a specific function. This way we can just use the mask to
    distinguish whether we should be checking the contents of a function.

    This namespace depends on the `tags` namespace to perform the conversions
    from tag names to their bit position. Reference counting is also handled by
    the aforementioned namespace.
    """
    name = 'minsc.tags.contents'

    statstag = schema.statstag
    NSUP_SCHEMA_VERSION = schema.NSUP_SCHEMA_VERSION

    ## tags
    addresstag = netnode.suptag
    usagetag = addresstag + 1
    ownershiptag = usagetag + 1

    # tags attached directly to a function
    counttag = usagetag + 1

    ## schema
    schema = {
        (netnode.sup, statstag): {
            NSUP_SCHEMA_VERSION: 1,
        },
        (netnode.sup, addresstag): {},
        (netnode.sup, usagetag): {},
        (netnode.alt, ownershiptag): {},

        # scoped to the function's netnode
        (netnode.alt, counttag): {},
    }

    ### classmethods that we need to implement. these use a netnode determined
    ### by the specified address in order to count tags applied to a function.

    @classmethod
    def hascount(cls, node, key, position, *tag, **kwargs):
        '''Return whether the reference count at the specified `key` exists for the tag at `position` of the netnode specified by `node`.'''
        return super(contents, cls).hascount(node, key, position, cls.counttag)

    @classmethod
    def getcount(cls, node, key, position, *tag, **kwargs):
        '''Return the reference count at the specified `key` for the tag at `position` of the netnode specified by `node`.'''
        return super(contents, cls).getcount(node, key, position, cls.counttag)

    @classmethod
    def setcount(cls, node, key, position, count, *tag, **kwargs):
        '''Set the reference count at the specified `key` for the tag at `position` of the netnode specified by `node` to `count`.'''
        return super(contents, cls).setcount(node, key, position, count, cls.counttag)

    @classmethod
    def getusage(cls, node, key, tag):
        '''Return the usage mask for the function `key` from the current netnode.'''
        node = cls.node()
        return super(contents, cls).getusage(node, key, cls.usagetag)

    @classmethod
    def setusage(cls, node, key, used, tag):
        '''Set the usage mask for the function `key` in the current netnode to the integer in `used`.'''
        node = cls.node()
        return super(contents, cls).setusage(node, key, used, cls.usagetag)

    ### regular methods

    @classmethod
    def get(cls, ea):
        '''Return all of the tags that are currently associated with the contents address `ea`.'''
        node = cls.node()
        return super(contents, cls).get(node, idaapi.ea2node(ea), cls.addresstag)

    # XXX: an address can have multiple owners, so we'll need to ensure all
    #      functions owning said address are updated.

    @classmethod
    def adjust_owners(cls, owners, key, name, adjustment):
        '''Adjust the reference count and usage for the tag `name` at `key` for each of the `owners`.'''
        usagenode, nodes = cls.node(), {owner : idaapi.ea2node(owner) for owner in owners}
        owners_description = "{{{:s}}}".format(','.join(map("{:#x}".format, sorted(owners))))
        with tags.transactional_adjust(name) as (position, tagcount):
            bit, clear = pow(2, position), ~pow(2, position)

            # get the reference count and the used tags for the given key in
            # each owner. we preserve these in case we need to rollback their
            # values later.
            iterable = ((owner, cls.hascount(nodes[owner], key, position, tag=cls.counttag)) for owner in nodes)
            counts = {owner : (cls.getcount(nodes[owner], key, position, tag=cls.counttag) if has else 0) for owner, has in iterable}
            usage = {owner : cls.getusage(usagenode, nodes[owner], tag=cls.usagetag) for owner in counts}

            # now we need to check the reference counts to ensure that our
            # increment does not cause an overflow.
            if adjustment > 0 and not all(count + adjustment < MAXIMUM_SPEC_INTEGER for node, count in counts.items()):
                overflown = {node for node, count in counts.items() if not(count + adjustment < MAXIMUM_SPEC_INTEGER)}
                count = max({count for _, count in counts.items()})
                bits = count.bit_count() if hasattr(count, 'bit_count') else "{:b}".format(count).count('1')
                raise OverflowError(u"{:s}.adjust_owners({:s}, {:#x}, {!s}, {:+d}) : Unable to increment ({:+d}) the reference count ({:d}) for the specified tag ({!s}) due to the current count already being at its maximum number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), owners_description, key, "{!r}".format(name), adjustment, adjustment, count, "{!r}".format(name), bits))

            # we also check for underflow in all the owners too. however, it's
            # worth noting that some owners might not have this tag due to a
            # previous target-specific decrement. so, to avoid interrupting the
            # user with something they can't fix, we just log what happened.
            elif adjustment < 0 and not all(count + adjustment >= 0 for node, count in counts.items()):
                underflown = {node for node, count in counts.items() if not(count + adjustment >= 0)}
                count = min({count for _, count in counts.items()})
                bits = count.bit_count() if hasattr(count, 'bit_count') else "{:b}".format(count).count('1')
                logging.info(u"{:s}.adjust_owners({:s}, {:#x}, {!s}, {:+d}) : Ignoring inability to decrement ({:+d}) the reference count ({:d}) for the specified tag ({!s}) due to the current count already being at its minimum number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), owners_description, key, "{!r}".format(name), adjustment, adjustment, count, "{!r}".format(name), bits))

            # next we'll need to figure out what to update each owner (mask and
            # count) with so that we can update each of them one-by-one. we
            # start by creating dicts for updating (set/clear) the usage mask
            # and then creating another for updating the reference count.
            setting = {owner : used | bit for owner, used in usage.items()}
            clearing = {owner : used & clear for owner, used in usage.items()}

            newcounts = {owner : count + adjustment for owner, count in counts.items()}
            iterable = ((owner, newcounts[owner]) for owner in nodes)
            newused = {owner : (setting[owner] if newcount > 0 else clearing[owner]) for owner, newcount in iterable if newcount != counts[owner]}

            # update them one-by-one, adjusting the reference count too. if
            # anything fails, then the transaction gets aborted by an exception.
            try:
                failed = {}
                for owner, newcount in newcounts.items():
                    ok_count = cls.setcount(nodes[owner], key, position, newcount, tag=cls.counttag)
                    ok_mask = owner not in newused or cls.setusage(usagenode, nodes[owner], newused[owner], tag=cls.usagetag)
                    if ok_count and ok_mask:
                        position, count = tagcount.send(adjustment)

                    # if we couldn't set the mask or count, then stash away our
                    # failure and the count that we'll be restoring it to.
                    else:
                        failed[owner] = counts[owner]
                    continue

                # if anything failed, then we need to raise an exception here so
                # that the transaction can be aborted.
                if failed:
                    failure_description = ', '.join(map("{:#x}".format, sorted(failed)))
                    raise exceptions.DisassemblerError(u"{:s}.adjust_owners({:s}, {:#x}, {!s}, {:+d}) : Unable to update the key at {:#x} of the specified netnodes ({:s}) for the given tag ({!s}).".format('.'.join([__name__, cls.__name__]), owners_description, key, "{!r}".format(name), adjustment, key, failure_description, "{!r}".format(name)))

            # if we caught an exception, then we need to restore all of the
            # masks that we've modified with the previous loop. afterwards, we
            # can send the exception to the coroutine to abort the transaction.
            except Exception as E:
                for owner, count in counts.items():
                    used = usage[owner]
                    bits = used.bit_count() if hasattr(used, 'bit_count') else "{:b}".format(used).count('1')
                    logging.info(u"{:s}.adjust_owners({:s}, {:#x}, {!s}, {:+d}) : Rolling back the usage mask and reference count for the specified key ({:#x}) of netnode {:#x} to its previous number of bits ({:d}) and value ({:d}).".format('.'.join([__name__, cls.__name__]), owners_description, key, "{!r}".format(name), adjustment, key, owner, bits, count))
                    if not cls.setcount(nodes[owner], key, position, count, tag=cls.counttag):
                        logging.error(u"{:s}.adjust_owners({:s}, {:#x}, {!s}, {:+d}) : Unable to roll back the reference count for the specified key ({:#x}) of netnode {:#x} to its previous value ({:d}).".format('.'.join([__name__, cls.__name__]), owners_description, key, "{!r}".format(name), adjustment, key, owner, count))
                    elif not cls.setusage(usagenode, owner, used, tag=cls.usagetag):
                        logging.error(u"{:s}.adjust_owners({:s}, {:#x}, {!s}, {:+d}) : Unable to roll back the usage mask for the specified key ({:#x}) of netnode {:#x} to its previous number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), owners_description, key, "{!r}".format(name), adjustment, key, owner, bits))
                    continue

                # then we passthrough our exception to abort the transaction.
                tagcount.throw(E)

            # grab everything that was written, and make sure that everything
            # we did matches what was expected.
            written = {owner : cls.getusage(usagenode, nodes[owner], tag=cls.usagetag) for owner, _ in newused.items()}
            adjusted = {owner : cls.getcount(nodes[owner], key, position, tag=cls.counttag) for owner, newcount in newcounts.items()}
            if not all(newused[owner] == used for owner, used in written.items()):
                missed = {owner for owner, used in written.items() if used != newused[owner]}
                raise AssertionError(u"{:s}.adjust_owners({:s}, {:#x}, {!s}, {:+d}) : Error updating the usage masks for the key at {:#x} of the specified netnodes ({:s}).".format('.'.join([__name__, cls.__name__]), owners_description, key, "{!r}".format(name), adjustment, key, ', '.join(map("{:#x}".format, missed))))

            # a "newcount" can be <0, which means that the tag was removed from
            # an owner that didn't actually own the address. since we want to
            # avoid storing more information in the netnode for an owner, we
            # have no good way of identifying whether an address is actually
            # owned other than the address being included in the owner's range.
            elif not all(max(0, newcounts[owner]) == count for owner, count in adjusted.items()):
                missed = {owner for owner, count in adjusted.items() if count != newcounts[owner]}
                raise AssertionError(u"{:s}.adjust_owners({:s}, {:#x}, {!s}, {:+d}) : Error updating the reference count for the key at {:#x} of the specified netnodes ({:s}).".format('.'.join([__name__, cls.__name__]), owners_description, key, "{!r}".format(name), adjustment, key, ', '.join(map("{:#x}".format, missed))))
            return position, newcounts
        return position, newcounts

    @classmethod
    @contextlib.contextmanager
    def adjust_tags(cls, ea, position, target=None):
        '''Adjust the used tags and ownership count for the tag `position` at the contents address specified by `ea`.'''
        owners = interface.function.owners(ea) if target is None else {target if isinstance(target, internal.types.integer) else interface.range.start(target)}
        targets = owners if target is None else {target if isinstance(target, internal.types.integer) else interface.range.start(target)}

        # convert our parameters into a format that makes them easy to use.
        node, nodes = cls.node(), {owner : idaapi.ea2node(owner) for owner in targets}
        target_description = '' if target is None else ", target={:#x}".format(*targets)

        # use the bit position to precalculate some integers that can be used
        # for setting and clearing the tags. grab the mask for the address too
        # in case it needs to be restored later.
        bit, clear = pow(2, position), ~pow(2, position)
        ownership =  netnode.alt.get(node, idaapi.ea2node(ea), tag=cls.ownershiptag) if netnode.alt.has(node, idaapi.ea2node(ea), tag=cls.ownershiptag) else 0
        used = suptools.bigint(node, idaapi.ea2node(ea), tag=cls.addresstag)

        # Define a closure that we will use to track how the ownership count for
        # the address will be updated. This way if the caller fails while doing
        # anything, we can avoid committing the changes that were made.
        def adjustment_closure(ea, ownership):
            '''This coroutine will receive amounts that will be used to adjust the current ownership count for the address `ea`.'''
            adjustment = 0
            try:
                while True:
                    amount = (yield ea, ownership + adjustment)

                    # Check that our adjustments will fit within the netnode.
                    if not(ownership + adjustment + amount < MAXIMUM_SPEC_INTEGER):
                        raise OverflowError(u"{:s}.adjust_tags({:#x}, {:d}{:s}) : Unable to adjust the ownership count by {:+d} for the address {:#x} due to the result being larger than the maximum value ({:#x}{:+#x}).".format('.'.join([__name__, cls.__name__]), ea, position, target_description, amount, ea, ownership, adjustment))

                    # If the adjustment of the ownership count is less than 0,
                    # then the number of targets being updated is larger than
                    # the number of targets that own the address. This can only
                    # occur when no target is specified for an address. In this
                    # case, we just lodge a complain with an authority figure.
                    elif ownership + adjustment + amount < 0:
                        logging.info(u"{:s}.adjust_tags({:#x}, {:d}{:s}) : The number of owners ({:d}) for the contents address at {:#x} is smaller than the requested adjustment ({:d}) and will be ignored.".format('.'.join([__name__, cls.__name__]), ea, position, target_description, ownership, ea, ownership, adjustment + amount))

                    # Now we can adjust the ownership count and try again.
                    adjustment += amount

            # If the generator finished, then we can apply our adjustments.
            except GeneratorExit:
                if not (ownership + adjustment < MAXIMUM_SPEC_INTEGER):
                    raise OverflowError(u"{:s}.adjust_tags({:#x}, {:d}{:s}) : Aborting the transaction to set the ownership count for address ({:#x}) from its previous value ({:d}) to an out-of-bounds value ({:d}).".format('.'.join([__name__, cls.__name__]), ea, position, target_description, ea, ownership, ownership + adjustment))

                newownership = ownership + adjustment

            # If our caller raised an exception, then discard the transaction
            # and re-raise the exception so that the caller can handle cleanup.
            except:
                logging.info(u"{:s}.adjust_tags({:#x}, {:d}{:s}) : Aborting the transaction to set the ownership count for address ({:#x}) from its previous value ({:d}) to a new value ({:d}).".format('.'.join([__name__, cls.__name__]), ea, position, target_description, ea, ownership, ownership + adjustment))
                raise

            # now we need to figure out whether we're need to adjust the usage
            # for the address by setting it or clearing it. if we couldn't do
            # it, then raise an exception and let the caller figure shit out.
            newused = used | bit if newownership > 0 else used & clear
            if not suptools.setbigint(node, idaapi.ea2node(ea), newused, tag=cls.addresstag):
                raise exceptions.DisassemblerError(u"{:s}.adjust_tags({:#x}, {:d}{:s}) : Unable to set the used tags for address {:#x} in the netnode {:#x} to its new value ({:d}).".format('.'.join([__name__, cls.__name__]), ea, position, target_description, ea, node, newused))

            # next we need to update the ownership count for the address. this
            # depends on whether the address is owned by a function, where
            # "ownership" is > 0, or not...which requires us to remove it.
            if newownership > 0:
                ok = netnode.alt.set(node, idaapi.ea2node(ea), newownership, tag=cls.ownershiptag)
            elif netnode.alt.has(node, idaapi.ea2node(ea), tag=cls.ownershiptag):
                ok = netnode.alt.remove(node, idaapi.ea2node(ea), tag=cls.ownershiptag)
            else:
                ok = True

            if not ok:
                raise exceptions.DisassemblerError(u"{:s}.adjust_tags({:#x}, {:d}{:s}) : Unable to set the ownership count for address {:#x} in the netnode {:#x} to its new value ({:d}).".format('.'.join([__name__, cls.__name__]), ea, position, target_description, ea, node, newownership))
            return

        # instantiate our coroutine, and return it so that it can be used to
        # adjust the ownership count for the specified address.
        coroutine = adjustment_closure(ea, ownership); next(coroutine)
        try:
            yield ea, coroutine

            # The caller should've submitted all the adjustments to the
            # coroutine, so we should be able to safely close it.
            coroutine.close()

        # If an exception was raised while our coroutine exits, then we need to
        # abandon the changes we were planning to commit.
        except:
            logging.info(u"{:s}.adjust_tags({:#x}, {:d}{:s}) : Rolling back the state of the tags applied to the contents address at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, position, target_description, ea))

            # Roll back the used tags mask for the specified address.
            bits = used.bit_count() if hasattr(used, 'bit_count') else "{:b}".format(used).count('1')
            logging.info(u"{:s}.adjust_tags({:#x}, {:d}{:s}) : Rolling back the used tags for the contents address at {:#x} to its previous number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), ea, position, target_description, ea, bits))
            if not suptools.setbigint(node, idaapi.ea2node(ea), used, tag=cls.addresstag):
                logging.error(u"{:s}.adjust_tags({:#x}, {:d}{:s}) : Unable to roll back the used tags for the contents address at {:#x} to its previous number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), ea, position, target_description, ea, bits))

            # Roll back the ownership count to the original value, removing it
            # if it exists and the old count is less than or equal to 0.
            logging.info(u"{:s}.adjust_tags({:#x}, {:d}{:s}) : Rolling back the ownership count for the contents address at {:#x} to its previous value ({:d}).".format('.'.join([__name__, cls.__name__]), ea, position, target_description, ea, ownership))
            if ownership > 0:
                ok = netnode.alt.set(node, idaapi.ea2node(ea), ownership, tag=cls.ownershiptag)
            elif netnode.alt.has(node, idaapi.ea2node(ea), tag=cls.ownershiptag):
                ok = netnode.alt.remove(node, idaapi.ea2node(ea), tag=cls.ownershiptag)
            else:
                ok = True

            if not ok:
                logging.error(u"{:s}.adjust_tags({:#x}, {:d}{:s}) : Unable to roll back the ownership count for the contents address at {:#x} to its previous value ({:d}).".format('.'.join([__name__, cls.__name__]), ea, position, target_description, ea, ownership))
            raise
        return

    @classmethod
    def increment(cls, ea, name, target=None):
        '''Increment the reference count for the tag with the specified `name` at the contents address `ea`.'''
        owners = interface.function.owners(ea) if target is None else {target if isinstance(target, internal.types.integer) else interface.range.start(target)}
        targets = owners if target is None else {target if isinstance(target, internal.types.integer) else interface.range.start(target)}

        # convert our parameters into a format that makes them easy to use, and
        # get the tag position so that we can adjust the used tags and ownership
        # count for the address.
        node, nodes = cls.node(), {owner : idaapi.ea2node(owner) for owner in targets}
        target_description = '' if target is None else ", target={:#x}".format(*targets)

        # figure out whether the tag already exists or not so that we know which
        # function to use in order to roll things back to the original value.
        Ftagdiscard, Ftagcreate = (tags.get, tags.get) if tags.has(name) else (tags.discard, tags.add)
        (position, count) = Ftagcreate(name)

        # now we can adjust the used tags for the address and update the usage
        # mask for each owner. if an exception gets raised during the update of
        # the tags for the address, then the "adjust_tags" context manager will
        # roll back the settings that it applied.
        try:
            with cls.adjust_tags(ea, position, target=target) as (ea, updater):
                result = cls.adjust_owners(targets, idaapi.ea2node(ea), name, +1)
                [ updater.send(+1) for owner in targets]

        # if an exception was raised, then we need to roll things back. the
        # context managers are responsible for themselves, so we only need to
        # discard the tag if we created it before our adjustments.
        except:
            logging.info(u"{:s}.increment({:#x}, {!s}{:s}) : Rolling back the tag \"{:s}\" that was created for the contents address at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, "{!r}".format(name), target_description, utils.string.escape(name, '"'), ea))
            (position, count) = Ftagdiscard(name)
            raise

        return result

    @classmethod
    def decrement(cls, ea, name, target=None):
        '''Decrement the reference count for the tag with the specified `name` at the contents address `ea`.'''
        owners = interface.function.owners(ea) if target is None else {target if isinstance(target, internal.types.integer) else interface.range.start(target)}
        targets = owners if target is None else {target if isinstance(target, internal.types.integer) else interface.range.start(target)}

        # grab our parameters, and convert them into an easy lookup table.
        node, nodes = cls.node(), {owner : idaapi.ea2node(owner) for owner in targets}
        target_description = '' if target is None else ", target={:#x}".format(*targets)

        # try and get the bit position for the tag. if the tag doesn't exist,
        # then we can't decrement it anyways (obviously).
        if not(tags.has(name)):
            raise exceptions.MissingTagError(u"{:s}.decrement({:#x}, {!s}{:s}) : Unable to decrement the reference count of the specified tag ({!s}) due to the tag not being available.".format('.'.join([__name__, cls.__name__]), ea, "{!r}".format(name), target_description, "{!r}".format(name)))
        position, count = tags.get(name)

        # we can now just adjust the tags for the specified address, and ensure
        # that the usage mask for each function owning that address is also
        # updated. we don't need to trap for any kind of exception since we use
        # the context managers which are responsible for their own exceptions.
        with cls.adjust_tags(ea, position, target=target) as (ea, updater):
            result = cls.adjust_owners(targets, idaapi.ea2node(ea), name, -1)
            [ updater.send(-1) for owner in targets ]
        return result

    @classmethod
    def usage(cls, func):
        '''Return the usage mask containing tags used in the contents for the function `func`.'''
        node, key = cls.node(), idaapi.ea2node(func)
        return cls.getusage(node, key, cls.usagetag)

    @classmethod
    def forward(cls, *ea):
        '''Yield the address and mask for each tag starting from the contents address `ea` (if given).'''
        node = cls.node()
        for key, integer in super(contents, cls).forward(node, *map(idaapi.ea2node, ea), tag=cls.addresstag):
            yield idaapi.node2ea(key), integer
        return

    @classmethod
    def backward(cls, *ea):
        '''Yield the address and mask for each tag in reverse from the contents address `ea` (if given).'''
        node = cls.node()
        for key, integer in super(contents, cls).backward(node, *map(idaapi.ea2node, ea), tag=cls.addresstag):
            yield idaapi.node2ea(key), integer
        return

    @classmethod
    def range(cls, start, stop):
        '''Return a list containing the content addresses and masks from the address `start` to `stop`.'''
        node = cls.node()
        items = super(contents, cls).range(node, idaapi.ea2node(start), idaapi.ea2node(stop), tag=cls.addresstag)
        return [(idaapi.node2ea(key), integer) for key, integer in items]

    @classmethod
    def function(cls, func):
        '''Yield each content address and mask belonging to the function `func`.'''
        fn = interface.function.by(func)
        chunks = interface.function.chunks(fn)
        ranges = map(interface.range.unpack, chunks)

        # now we just need to iterate through each range and yield each item.
        iterables = (cls.range(*bounds) for bounds in ranges)
        for ea, integer in itertools.chain(*iterables):
            yield ea, integer
        return

    @classmethod
    def erase_usage(cls, func):
        '''Remove the usage mask and reference counts for the function `func`.'''
        node, parameter = cls.node(), "{:#x}".format(func) if isinstance(func, types.integer) else "{:s}".format(interface.range.bounds(func))
        fn = func if isinstance(func, (types.integer, idaapi.func_t)) else interface.function.by(func)
        address = fn if isinstance(fn, types.integer) else interface.range.start(fn)
        key = idaapi.ea2node(address)

        # First delete any reference counts for the tags used by the function.
        for position in netnode.alt.fiter(key, cls.counttag):
            if not(netnode.alt.has(key, position, tag=cls.counttag)):
                continue
            elif netnode.alt.remove(key, position, tag=cls.counttag):
                continue
            logging.error(u"{:s}.erase({!s}, {:#x}, {:#x}) : Unable to remove the reference count for the specified tag ({:d}) from netnode {:#x}.".format('.'.join([__name__, cls.__name__]), parameter, start, stop, position, key))

        # Grab the usage for the function and remove it if it actually exists.
        usage = cls.getusage(node, key, cls.usagetag)
        if netnode.sup.has(node, key, tag=cls.usagetag) and not(netnode.sup.remove(node, key, tag=cls.usagetag)):
            logging.error(u"{:s}.erase_usage({!s}) : Unable to remove the usage mask for the function at {:#x} from netnode {:#x}.".format('.'.join([__name__, cls.__name__]), parameter, address, node))
        return usage

    @classmethod
    def erase_bounds(cls, func, start, stop):
        '''Remove the contents for the function `func` from the address `start` to `stop`.'''
        node, parameter = cls.node(), "{:#x}".format(func) if isinstance(func, types.integer) else "{:s}".format(interface.range.bounds(func))
        fn = func if isinstance(func, (types.integer, idaapi.func_t)) else interface.function.by(func)
        address = fn if isinstance(fn, types.integer) else interface.range.start(fn)

        owner, deleting = idaapi.ea2node(address), {ea : used for ea, used in cls.range(start, stop)}
        for ea, used in deleting.items():
            key = idaapi.ea2node(ea)
            for position in tags.explode(used):
                if not cls.hascount(owner, key, position, tag=cls.counttag):
                    cls.setcount(owner, key, position, 1, tag=cls.counttag)
                cls.decrement(ea, position, target=address)
            continue
        return sorted(deleting)

    @classmethod
    def erase(cls, func):
        '''Remove the contents, masks, and reference counts for the function `func`.'''
        node, parameter = cls.node(), "{:#x}".format(func) if isinstance(func, types.integer) else "{:s}".format(interface.range.bounds(func))
        fn = func if isinstance(func, (types.integer, idaapi.func_t)) and netnode.sup.has(node, idaapi.ea2node(func), cls.usagetag) else interface.function.by(func)
        address = fn if isinstance(fn, types.integer) else interface.range.start(fn)

        key = idaapi.ea2node(address)
        if netnode.sup.has(node, key, usagetag) and not(netnode.sup.remove(node, key, cls.usagetag)):
            logging.error(u"{:s}.erase({!s}) : Unable to remove the usage mask for the function at {:#x} from netnode {:#x}.".format('.'.join([__name__, cls.__name__]), parameter, address, node))

        for position in netnode.alt.fiter(key, cls.counttag):
            if not(netnode.alt.has(key, position, tag=cls.counttag)):
                continue
            elif netnode.alt.remove(key, position, tag=cls.counttag):
                continue
            logging.error(u"{:s}.erase({!s}) : Unable to remove the reference count for the specified tag ({:d}) from netnode {:#x}.".format('.'.join([__name__, cls.__name__]), parameter, position, key))

        # now we need to remove the address mask for this entire function. we
        # need to be cautious, though, as we only want addresses that aren't
        # being referenced by another function. we accomplish this by building a
        # lookup table for the owner of every chunk so that we can check its
        # usage mask to ensure that its not using the address.
        chunks = interface.function.chunks(fn)
        ranges = map(interface.range.unpack, chunks)
        iterable = map(interface.function.owners, (left for left, _ in ranges))
        owners = {owner for owner in itertools.chain(*iterable)}
        usage = {owner : cls.usage(owner) for owner in owners}

        # FIXME: more than one function can be associated with an address.
        #        because of this, there's no way to tell whether all of the tags
        #        have been removed from an address since it might be being used
        #        by a different owner.
        deleting = {ea : used for ea, used in cls.function(fn)}
        for ea, used in deleting.items():
            for position in tags.explode(used):

                # if our count doesn't exist, due to a discrepancy (corruption),
                # then set it to 1 so that we can decrement without issue.
                for owner in map(idaapi.ea2node, owners):
                    if not cls.hascount(owner, idaapi.ea2node(ea), position, tag=cls.counttag):
                        cls.setcount(owner, idaapi.ea2node(ea), position, 1, tag=cls.counttag)
                    continue
                cls.decrement(ea, position, target=fn)
            continue
        return sorted(deleting)

    @classmethod
    def select(cls, *ea):
        '''Yield the function address and usage for the contents of each function in the database.'''
        node = cls.node()
        for key, integer in super(contents, cls).forward(node, *map(idaapi.ea2node, ea), tag=cls.usagetag):
            yield idaapi.node2ea(key), integer
        return

    @classmethod
    def repr(cls, *pattern):
        '''Display the contents of the index containing information about the function contents in the database.'''
        Fmatch = re.compile(fnmatch.translate(*pattern), re.IGNORECASE).match if pattern else utils.fconstant(True)
        usageresults = suptools.fall(cls.node(), tag=cls.usagetag)

        lines = []
        lines.append(u"Schema version: {:d}".format(cls.version()))

        listable = [','.join(map("{:d}".format, tags.explode(integer))) for ea, integer in usageresults if Fmatch("{:#x}".format(ea))]
        positions_width = max(map(len, listable)) if listable else 0

        # FIXME: would be nice to display the reference counts for each function.

        usage = [(u'Usage tags:')]
        for key, integer in usageresults:
            ea = idaapi.node2ea(key)
            if not Fmatch("{:#x}".format(ea)):
                continue
            exploded = ','.join(map("{:d}".format, tags.explode(integer)))
            usage.append("{:s}: {:<{:d}s} : {!s}".format("{:#x}".format(ea) if ea == key else "{:#x} ({:#x})".format(ea, key), exploded, positions_width, tags.names(integer)))
        lines.extend(itertools.chain(usage, [''] if usage else []))

        items = [(key, integer) for key, integer in suptools.forward(cls.node(), tag=cls.addresstag)]
        listable = [','.join(map("{:d}".format, tags.explode(integer))) for ea, integer in items if Fmatch("{:#x}".format(idaapi.node2ea(ea)))]
        positions_width = max(map(len, listable)) if listable else 0

        lines.append(u'Contents with tags:')
        for key, integer in items:
            ea = idaapi.node2ea(key)
            if not Fmatch("{:#x}".format(ea)):
                continue
            exploded = ','.join(map("{:d}".format, tags.explode(integer)))
            lines.append("{:s}: {:<{:d}s} : {!s}".format("{:#x}".format(ea) if ea == key else "{:#x} ({:#x})".format(ea, key), exploded, positions_width, tags.names(integer)))
        return '\n'.join(lines)

class members(counted):
    """
    This namespace is used to maintain the tag state for all of the structure or
    union members in the database. Each tag is identified by its member
    identifier and the tag names that are associated with said member. Similar
    to `globals` or `contents` tags, we use a "supval" with an integer that we
    encode/decode ourselves.

    This depends on the `tags` namespace to perform all the conversion and do
    the reference counting.
    """
    name = 'minsc.tags.members'

    statstag = schema.statstag
    NSUP_SCHEMA_VERSION = schema.NSUP_SCHEMA_VERSION

    ## tags
    membertag = netnode.suptag
    usagetag = membertag + 1

    # tags attached directly to a structure
    counttag = usagetag + 1

    ## schema
    schema = {
        (netnode.sup, statstag): {
            NSUP_SCHEMA_VERSION: 1,
        },
        (netnode.sup, membertag): {},
        (netnode.sup, usagetag): {},

        (netnode.alt, counttag): {},
    }

    # FIXME: we need to track when members are created or destroyed using a hook.

    ## classmethods that we're required to implement in order to track the
    ## reference count for the tags applied to a structure/union.

    @classmethod
    def hascount(cls, node, mid, position, *tag):
        '''Return whether the reference count in the member `mid` exists for the tag at `position` of the netnode specified by `node`.'''
        sptr, mindex, mptr = internal.structure.members.by_identifier(None, mid)
        countnode, counttag = netnode.get(sptr.id), cls.counttag
        return super(members, cls).hascount(countnode, mid, position, counttag)

    @classmethod
    def getcount(cls, node, mid, position, *tag):
        '''Return the reference count for the tag at `position` in the member `mid` of the netnode specified by `node`.'''
        sptr, mindex, mptr = internal.structure.members.by_identifier(None, mid)
        countnode, counttag = netnode.get(sptr.id), cls.counttag
        return super(members, cls).getcount(countnode, mid, position, counttag)

    @classmethod
    def setcount(cls, node, mid, position, count, *tag):
        '''Set the reference count for the tag at `position` in the member `mid` of the netnode specified by `node` to `count`.'''
        sptr, mindex, mptr = internal.structure.members.by_identifier(None, mid)
        countnode, counttag = netnode.get(sptr.id), cls.counttag
        return super(members, cls).setcount(countnode, mid, position, count, counttag)

    @classmethod
    def getusage(cls, node, mid, tag):
        '''Return the usage mask for the tags used by the members of structure owning the member `mid`.'''
        sptr, mindex, mptr = internal.structure.members.by_identifier(None, mid)
        usagenode, usagetag = cls.node(), cls.usagetag
        return super(members, cls).getusage(usagenode, sptr.id, usagetag)

    @classmethod
    def setusage(cls, node, mid, used, tag):
        '''Set the usage mask for the tags used by the members of structure owning the member `mid` to the integer in `used`.'''
        sptr, mindex, mptr = internal.structure.members.by_identifier(None, mid)
        usagenode, usagetag = cls.node(), cls.usagetag
        return super(members, cls).setusage(usagenode, sptr.id, used, usagetag)

    ## regular methods that we only override to hide any arguments that we can
    ## figure out by ourselves.

    @classmethod
    def get(cls, mid):
        '''Return all of the tags that are currently associated with the member in `mid`.'''
        node = cls.node()
        return super(members, cls).get(node, mid, cls.membertag)

    @classmethod
    def increment(cls, mid, name):
        '''Increment the reference count for the tag with the specified `name` from the member id specified in `mid`.'''
        node = cls.node()
        position, count = tags.get(name) if tags.has(name) else tags.add(name)
        return super(cls, members).increment(node, mid, position, tag=cls.membertag)

    @classmethod
    def decrement(cls, mid, name):
        '''Decrement the reference count for the tag with the specified `name` from the member id specified in `mid`.'''
        node = cls.node()
        if not(tags.has(name)):
            raise exceptions.MissingTagError(u"{:s}.decrement({:#x}, {!s}) : Unable to decrement the reference count of the specified tag ({!s}) due to the tag not being available.".format('.'.join([__name__, cls.__name__]), mid, "{!r}".format(name), "{!r}".format(name)))
        position, count = tags.get(name)
        return super(members, cls).decrement(node, mid, position, tag=cls.membertag)

    @classmethod
    def usage(cls, sid):
        '''Return the usage mask containing tags used by the members of structure `sid`.'''
        if internal.structure.has(sid):
           return super(members, cls).getusage(cls.node(), sid, cls.usagetag)
        return cls.getusage(cls.node(), sid, cls.usagetag)

    @classmethod
    def forward(cls, *mid):
        '''Yield the member id and mask for each tagged member in order starting at the member id in `mid` (if given).'''
        node = cls.node()
        for mid, integer in super(members, cls).forward(node, *mid, cls.membertag):
            yield mid, integer
        return

    @classmethod
    def backward(cls, *mid):
        '''Yield the member id and mask for each tagged member in reverse order starting at the member id in `mid` (if given).'''
        node = cls.node()
        for mid, integer in super(members, cls).backward(node, *mid, cls.membertag):
            yield mid, integer
        return

    @classmethod
    def range(cls, start, stop):
        '''Return a list of each member and mask from the member id `start` to `stop`.'''
        node = cls.node()
        items = super(members, cls).range(node, start, stop, tag=cls.membertag)
        return [(mid, integer) for mid, integer in items]

    @classmethod
    def structure(cls, sids):
        '''Yield the member id and mask for each member of the structures in `sids`.'''
        iterable = sids if isinstance(sids, types.unordered) else [sids]
        selected = {sid for sid in iterable}
        iterable = itertools.chain(*map(internal.structure.members.iterate, selected))
        identifiers = ((sptr.id, mptr.id) for sptr, mindex, mptr in iterable)
        requested = {mid for mowner, mid in identifiers if mowner in selected}

        # now that we have a set of requested member ids, we can iterate through
        # the entire table and only yield the ones that are requested.
        node = cls.node()
        for mid, integer in suptools.forward(node, tag=cls.membertag):
            if mid in requested:
                yield mid, integer
            continue
        return

    @classmethod
    def select(cls, *sids):
        '''Yield each structure and mask used by its members for every structure in `sids` (if given).'''
        iterable = itertools.chain(sids if sids else [])
        node, requested = cls.node(), {getattr(sid, 'id', sid) for sid in iterable}
        for sid, integer in suptools.forward(node, tag=cls.usagetag):
            if not(requested) or (sid in requested):
                yield sid, integer
            continue
        return

    @classmethod
    def erase(cls, sid, *mids):
        '''Remove the references for every member specified in `mids` belonging to the structure `sid`.'''
        node, countnode, counttag = cls.node(), netnode.get(sid), cls.counttag
        [mids] = mids if mids else [[item for item, _ in cls.structure(sid)]]
        iterable = [mids] if isinstance(mids, types.integer) else mids
        selected = {mid : suptools.bigint(node, mid, cls.membertag) for mid in iterable}
        usage = super(members, cls).getusage(node, sid, cls.usagetag)

        removed = {mid for mid in []}
        for mid, used in selected.items():
            for position in tags.explode(used):
                bit, clear = pow(2, position), ~pow(2, position)
                count = super(members, cls).getcount(countnode, mid, position, counttag)
                super(members, cls).setcount(countnode, mid, position, max(0, count - 1), counttag)
                if not(count > 1):
                    usage &= clear
                tags.decrement(position)
            removed.add(mid) if used else removed
            suptools.setbigint(node, mid, 0, cls.membertag)
        super(members, cls).setusage(node, sid, usage, cls.usagetag)
        return sorted(removed)

    @classmethod
    def repr(cls, *pattern):
        '''Display the contents of the index containing information about the structure members in the database.'''
        Fmatch = re.compile(fnmatch.translate(*pattern), re.IGNORECASE).match if pattern else utils.fconstant(True)
        items = suptools.fall(cls.node(), tag=cls.membertag)

        members = []
        for index, (mid, integer) in enumerate(items):
            if internal.structure.member.has(mid):
                sptr, mindex, mptr = internal.structure.members.by_identifier(None, mid)
                fullname = internal.structure.member.fullname(mptr)
            else:
                mptr, fullname = None, u'<REMOVED>'
            names = tags.names(integer)
            members.append((index, mid, mptr, integer, fullname, names))

        maxname = max(len(name) for _, _, _, _, name, _ in members) if members else 0
        maxtags = max(len("{!s}".format(names)) for _, _, _, _, _, names in members) if members else 0
        iterable = [','.join(map("{:d}".format, tags.explode(integer))) for _, _, _, integer, fullname, _ in members if Fmatch(fullname)]
        maxpositions = max(map(len, iterable)) if members else 0

        lines = []
        lines.append(u"Schema version: {:d}".format(cls.version()))

        # FIXME: we should display the usage mask for each structure and their
        #        reference counts.

        lines.append(u"Structure members with tags:")
        for index, mid, mptr, integer, fullname, names in members:
            if not Fmatch(fullname): continue
            iterable = (internal.structure.member.get_comment(mptr, boolean) for boolean in [True, False]) if mptr else ()
            filtered = [comment for comment in filter(None, iterable)]
            exploded = ','.join(map("{:d}".format, tags.explode(integer)))
            lines.append("[{:#x}] {:<{:d}s} : {:<{:d}s} : {:<{:d}s}{:s}".format(mid, fullname, maxname, exploded, maxpositions, "{!s}".format(names), maxtags, " // {!s}".format(filtered) if filtered else ''))
        return '\n'.join(lines)

class structure(schema):
    """
    This namespace is used to track the tags associated with all the structure
    or unions in the database. Each structure has two integers associated with
    it. This is to store the tags used by the structure/union itself, and to
    track the tags used by the members of the structure/union. We store these in
    two distinctly separate "supval" tables.

    Due to a limitation of the "supval" api where integers are limited by the
    maximum native word size of the database, we use the "supval" tables to
    store a string of bytes. These bytes contains the encoded integer for the
    tags associated with that specific item. Thus, when checking to see if a tag
    has been applied, the bytes will need to be decoded back to an integer.

    This depends on the `tags` namespace to perform all the conversion and do
    the reference counting.
    """
    name = 'minsc.tags.types'

    statstag = schema.statstag
    NSUP_SCHEMA_VERSION = schema.NSUP_SCHEMA_VERSION

    ## tags
    typetag = netnode.suptag

    ## schema
    schema = {
        (netnode.sup, statstag): {
            NSUP_SCHEMA_VERSION: 1,
        },
        (netnode.sup, typetag): {},
    }

    @classmethod
    def get(cls, sid):
        '''Return all of the tags that are currently associated with the structure id specified in `sid`.'''
        node = cls.node()
        res = suptools.bigint(node, sid, tag=cls.typetag)
        return tags.names(res)

    @classmethod
    def increment(cls, sid, name):
        '''Increment the reference count for the tag with the specified `name` of the structure id specified as `sid`.'''
        node = cls.node()
        position, count = tags.get(name) if tags.has(name) else tags.add(name)
        bit, clear = pow(2, position), ~pow(2, position)

        # query our table for any tags associated with the member id. if the tag
        # that we're incrementing is inside it, then there's nothing to do.
        res = suptools.bigint(node, sid, tag=cls.typetag)
        if res & bit:
            return position, count

        # otherwise we update the structure id with the bit for the incremented
        # tag. if we couldn't set the bit and write it, then abort.
        elif not suptools.setbigint(node, sid, res | bit, tag=cls.typetag):
            raise exceptions.DisassemblerError(u"{:s}.increment({:#x}, {!s}) : Unable to increment the reference count of the specified tag ({!s}) for structure {:#x} in the current netnode ({:#x}).".format('.'.join([__name__, cls.__name__]), sid, "{!r}".format(name), "{!r}".format(name), sid, node))

        # before leaving, we need to increase the reference count for the tag.
        try:
            result = tags.increment(position)

        # if we fail, tho, we need to undo the mask we just updated for the tag.
        except:
            bits = res.bit_count() if hasattr(res, 'bit_count') else "{:b}".format(res).count('1')
            logging.info(u"{:s}.increment({:#x}, {!s}) : Rolling back the used tags for structure {:#x} to its previous number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), sid, "{!r}".format(name), sid, bits))
            if not suptools.setbigint(node, sid, res, tag=cls.typetag):
                logging.error(u"{:s}.increment({:#x}, {!s}) : Unable to roll back the used tags for structure {:#x} to its previous number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), sid, "{!r}".format(name), sid, bits))
            raise
        return result

    @classmethod
    def decrement(cls, sid, name):
        '''Decrement the reference count for the tag with the specified `name` of the structure id specified as `sid`.'''
        node = cls.node()
        if not(tags.has(name)):
            raise exceptions.MissingTagError(u"{:s}.decrement({:#x}, {!s}) : Unable to decrement the reference count of the specified tag ({!s}) due to the tag not being available.".format('.'.join([__name__, cls.__name__]), sid, "{!r}".format(name), "{!r}".format(name)))

        # we need to clear the bit from the tags for the current structure, so
        # grab it and use it to calculate a mask that can be used for removal.
        position, count = tags.get(name)
        bit, clear = pow(2, position), ~pow(2, position)

        # next we need to check if the tag being decremented is already missing
        # from the structure. if so, then we don't have to do anything at all.
        res = suptools.bigint(node, sid, tag=cls.typetag)
        if not(res & bit):
            return position, count

        # if it's not missing, then we need to clear the bit position for the
        # tag from the tags associated with the structure id.
        elif not suptools.setbigint(node, sid, res & clear, tag=cls.typetag):
            raise exceptions.DisassemblerError(u"{:s}.decrement({:#x}, {!s}) : Unable to decrement the reference count of the specified tag ({!s}) for structure {:#x} in the current netnode ({:#x}).".format('.'.join([__name__, cls.__name__]), sid, "{!r}".format(name), "{!r}".format(name), sid, node))

        # now we can decrement the reference count for the tag itself.
        try:
            result = tags.decrement(position)

        # if doing that raised an exception, then we undo the used tags that
        # were applied to the structure id that was given.
        except:
            bits = res.bit_count() if hasattr(res, 'bit_count') else "{:b}".format(res).count('1')
            logging.info(u"{:s}.decrement({:#x}, {!s}) : Rolling back the used tags for structure {:#x} to its previous number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), sid, "{!r}".format(name), sid, bits))
            if not suptools.setbigint(node, sid, res, tag=cls.typetag):
                logging.error(u"{:s}.decrement({:#x}, {!s}) : Unable to roll back the used tags for structure {:#x} to its previous number of bits ({:d}).".format('.'.join([__name__, cls.__name__]), sid, "{!r}".format(name), sid, bits))
            raise
        return result

    @classmethod
    def usage(cls):
        '''Return the usage mask containing the tags applied to all of the structures.'''
        iterable = (integer for sid, integer in cls.forward())
        return functools.reduce(operator.or_, iterable, 0)

    @classmethod
    def forward(cls, *sid):
        '''Yield the structure id and mask for each tagged structure in order starting at the structure id `sid` (if given).'''
        node = cls.node()
        for sid, integer in super(structure, cls).forward(node, *sid, tag=cls.typetag):
            yield sid, integer
        return

    @classmethod
    def backward(cls, *sid):
        '''Yield the structure id and mask for each tagged structure in reverse order starting at the structure id `sid` (if given).'''
        node = cls.node()
        for sid, integer in super(structure, cls).backward(node, *sid, tag=cls.typetag):
            yield sid, integer
        return

    @classmethod
    def select(cls, structures):
        '''Yield the structure id and mask for each of the specified `structures`.'''
        node = cls.node()

        # convert the parameter into a list of structure identifiers.
        iterable = itertools.chain([structures] if isinstance(structures, types.integer) else structures)
        owners = sorted({getattr(sid, 'id', sid) for sid in iterable})

        # all we have to do now is to return the masks for the structure.
        iterable = ((sid, suptools.bigint(node, sid, tag=cls.typetag)) for sid in owners)
        for sid, integer in iterable:
            yield sid, integer
        return

    @classmethod
    def erase(cls, structures):
        '''Remove the structure id and mask for each of the specified `structures`.'''
        removed = {sid for sid in []}
        for sid, used in cls.select(structures):
            positions = tags.explode(used)
            if [cls.decrement(sid, position) for position in positions]:
                removed.add(sid)
            continue
        return sorted(removed)

    @classmethod
    def repr(cls, *pattern):
        '''Display the contents of the index containing information about the structures from the database.'''
        Fmatch = re.compile(fnmatch.translate(*pattern), re.IGNORECASE).match if pattern else utils.fconstant(True)
        items = suptools.fall(cls.node(), tag=cls.typetag)

        res = []
        for index, (sid, integer) in enumerate(items):
            if internal.structure.has(sid):
                sptr = idaapi.get_struc(sid)
                fullname = internal.structure.naming.get(sptr)
            else:
                sptr, fullname = None, u'<REMOVED>'
            names = tags.names(integer)
            res.append((index, sid, sptr, integer, fullname, names))

        maxname = max(len(name) for _, _, _, _, name, _ in res) if res else 0
        maxtags = max(len("{!s}".format(names)) for _, _, _, _, _, names in res) if res else 0
        iterable = [','.join(map("{:d}".format, tags.explode(integer))) for _, _, _, integer, fullname, _ in res if Fmatch(fullname)]
        maxpositions = max(map(len, iterable)) if res else 0

        lines = []
        lines.append(u"Schema version: {:d}".format(cls.version()))
        lines.append(u"Structures with tags:")
        for index, sid, sptr, integer, fullname, names in res:
            if not Fmatch(fullname): continue
            iterable = (internal.structure.comment.get(sptr, boolean) for boolean in [True, False]) if sptr else ()
            filtered = [utils.string.of(comment) for comment in filter(None, iterable)]
            exploded = ','.join(map("{:d}".format, tags.explode(integer)))
            lines.append("[{:#x}] {:<{:d}s} : {:<{:d}s} : {:<{:d}s}{:s}".format(sid, fullname, maxname, exploded, maxpositions, "{!s}".format(names), maxtags, " // {!s}".format(filtered) if filtered else ''))
        return '\n'.join(lines)
