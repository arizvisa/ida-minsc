"""
Tagcache module (internal)

This module is responsible for the original implementation of the tagging cache
(tagcache), and contains the necessary functionality for querying information
from the cache. This implementation revolves around tracking a reference count
for the number of tags applied to a global or contents address.

The tagcache stores its reference counts within the "$ tagcache" netnode. Some
function-specific data is also stored within the netnode for the corresponding
function. This is done through careful selection of the netnode tag used by the
"hashval", "altval", and "supval" that is stored within the relevant netnodes.

Each of these namespaces actually originate from the `internal.comment` module
prior to their existence here.
"""

import functools, operator, itertools, logging, bz2
import idaapi, ida, internal
from internal import utils, interface, netnode

class tagging(object):
    """
    This namespace is essentially the configuration of the tagging
    database. This configurations specifies how to marshal and
    compress reference counts that are retained by the tagging
    infrastructure.

    The keys for the dictionaries that store the reference count
    are named according to ``tagging.__tags__`` for the tag names
    and ``tagging.__address__`` for the tag addresses. In order
    to access the tagging database, the netnode is returned by
    the ``tagging.node()`` function.

    When a database has been successfully created, a hook is
    responsible for calling the ``tagging.__init_tagcache__()``
    function. This will then create a netnode with the name
    specified in ``tagging.__node__``.
    """
    __node__ = '$ tagcache'
    __tags__, __address__ = 'name', 'address'

    marshaller = __import__('marshal')
    codec = __import__('codecs').lookup('bz2_codec')

    @classmethod
    def __init_tagcache__(cls, idp_modname):
        '''Hook to create a new netnode that will contain our tag-cache.'''
        res = cls.node(cached=False)
        logging.debug(u"{:s}.init_tagcache('{:s}') : Successfully opened up the netnode \"{:s}\" for the tag cache and using the identifier ({:#x}) to reference it.".format('.'.join([__name__, cls.__name__]), internal.utils.string.escape(idp_modname, '\''), internal.utils.string.escape(cls.__node__, '"'), res))

    @classmethod
    def __nw_init_tagcache__(cls, nw_code, is_old_database):
        idp_modname = idaapi.get_idp_name()
        return cls.__init_tagcache__(idp_modname)

    @classmethod
    def node(cls, cached=True):
        '''Fetch the netnode containing the tag-cache which should be named "$ tagcache".

        If `cached` is changed to False, then always update the node's identifier.
        '''
        if cached and hasattr(cls, '__cache_id__'):
            return cls.__cache_id__

        # Explicitly try to fetch the netnode containing the tag-cache. If we were
        # unable to find it, then create it and use that instead.
        node = netnode.get(cls.__node__)
        if node == idaapi.BADADDR:
            node = netnode.new(cls.__node__)

        # Cache the identifier for the netnode inside a class attribute
        cls.__cache_id__ = node
        return node

class contents(tagging):
    """
    This namespace is used to update the tag state for any content tags
    associated with a function in the database. The address for the top
    of the function represents a key within the netnode that is used to
    fetch the blob and the supval which contains a marshall'd dictionary
    and a marshall'd set. These are stored within the `tagging.node()`
    netnode withn the tag `contents.btag`.

    The marshall'd dictionary that is stored in the netnode's blob is
    used to retain a dictionary of reference counts for both the tag
    names and the addresses that they reside at. Anytime a tag is
    written or removed, the reference count for both the name and the
    address is adjusted.

    Earlier versions of this implementation would store the marshall'd
    dictionary directly in the netnode for the function. As reported in
    issue #198, this can conflict with some processor modules. In order
    to remedy this condition, the implementation creates a completely
    separate netnode using the function address to avoid any conflict.
    If the netnode does not exist and the old location has a blob stored
    within it, then the blob is migrated into the new netnode.

    Due to a size limit of a blob, the supval for the tagging node is
    used to store the tag names that are used within a function as a
    marshall'd ``set``. This ``set`` is used to verify that the tag
    names within the contents of the function correspond with the
    reference count that is stored within the marshall'd dictionary
    in the blob.
    """

    ## for each function's content
    # netnode.blob[fn.start_ea, btag] = marshal.dumps({'name', 'address'})
    # netnode.sup[fn.start_ea] = marshal.dumps({tagnames})

    #btag = idaapi.stag         # XXX: apparently 'S' is used for comments
    #btag = idaapi.atag         # XXX: apparently 'A' is used for altvals

    # XXX: this tag conflicts with the altvals used by some disassembler
    #      architectures as a result of how blobs are stored within a netnode.
    #      so, to avoid interfering with the chosen disassembler we create our
    #      own netnode by prefixing the `tagging.__node__` string with the
    #      function address similar to the disassembler's format for a function
    #      netnode ("$ F10083200").
    btag = idaapi.atag

    @classmethod
    def _key(cls, ea):
        '''Converts the address `ea` to a key that's used to store contents data for the specified function.'''

        # First we'll need to verify that we're within a function, then
        # we can try and grab it and the chunk for the same address.
        res, ch = idaapi.get_func(ea), idaapi.get_fchunk(ea)
        if res is None or ch is None:
            return None
        owner, bounds = map(interface.range.bounds, [res, ch])

        # If we're a function tail, then there's a chance that the
        # owner of the function is owned by multiple functions.
        if ch.flags & idaapi.FUNC_TAIL:
            count, iterator = ch.refqty, idaapi.func_parent_iterator_t(ch)

            # Seek the iterator to its first position so we can grab each owner
            # for the chunk at the requested address. If we can't, then that's
            # okay because we can return the function unless the count is > 1.
            if not iterator.first():
                Flogging = logging.warning if count > 1 else logging.info
                Flogging(u"{:s}._key({:#x}) : Returning {:d} owner{:s}{:s} for the function tail at {!s} instead of {:d} due to being unable to seek with the initialized `{:s}`.".format('.'.join([__name__, cls.__name__]), ea, 1 if count else 0, '' if count else 's', " ({!s})".format(owner) if count else '', bounds, count, iterator.__class__.__name__))

                # Gather the single function into a list of items, and return
                # its starting address if our "refqty" is larger than 0.
                items = [owner] if count else []
                iterable = (ea for ea, _ in items)

            # Now we can grab the first parent address, and continue looping
            # while saving each parent that we get into our result list.
            else:
                items = [iterator.parent()]
                while iterator.next():
                    ea = iterator.parent()
                    items.append(ea)
                iterable = (ea for ea in items)

            # Last thing to do is to figure out whether we return a list,
            # a single address, or None if we didn't find anything.
            result = sorted(iterable)
            return result if len(result) > 1 else result[0] if result else None

        # Otherwise we can unpack our owner and return its start address.
        result, _ = owner
        return result

    @classmethod
    def _read_header(cls, target, ea):
        """Read the contents dictionary out of the supval belonging to the function at `target`.

        If `target` is ``None``, then use the address of the function containing `ea`.
        """
        node, key = cls.node(), cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._read_header({!r}, {:#x}) : Unable to locate a function for target ({!r}) at {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, key, ea))

        # If our key was a list, then we need to warn the user that
        # we're going to take a guess on which function we'll return.
        elif isinstance(key, internal.types.list):
            key, _ = key[0], logging.critical(u"{:s}._read_header({!r}, {:#x}) : Choosing to read header from function {:#x} for address {:#x} as it is owned by {:d} function{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), target, ea, key[0], ea, len(key), '' if len(key) == 1 else 's', ', '.join(map("{:#x}".format, key))))

        view = netnode.sup.get(node, key, type=memoryview)
        if view is None:
            return None
        encdata = view.tobytes()

        try:
            data, sz = cls.codec.decode(encdata)
            if len(encdata) != sz:
                raise internal.exceptions.SizeMismatchError(u"{:s}._read_header({!r}, {:#x}) : The number of bytes that was decoded did not match the expected size ({:#x}<>{:#x}).".format('.'.join([__name__, cls.__name__]), target, ea, sz, len(encdata)))
        except Exception as E:
            logging.warning(u"{:s}._read_header({!r}, {:#x}) : An exception {!r} was raised while trying to decode the cache header for address {:#x} from the sup cache associated with key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, E, ea, key), exc_info=True)
            logging.info(u"{:s}._read_header({!r}, {:#x}) : Error occurred while decoding the following data from the sup cache: {!r}.".format('.'.join([__name__, cls.__name__]), target, ea, encdata))
            raise internal.exceptions.SerializationError(u"{:s}._read_header({!r}, {:#x}) : Unable to decode the cache header for address {:#x} from the sup cache associated with key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, ea, key))

        try:
            result = cls.marshaller.loads(data)
        except Exception as E:
            logging.info(u"{:s}._read_header({!r}, {:#x}) : Error occurred while unmarshalling the following data from the sup cache: {!r}.".format('.'.join([__name__, cls.__name__]), target, ea, data))
            raise internal.exceptions.SerializationError(u"{:s}._read_header({!r}, {:#x}) : Unable to unmarshal the cache header for address {:#x} from the sup cache associated with key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, ea, key))
        return result

    @classmethod
    def _write_header(cls, target, ea, value):
        """Write the specified `value` into the contents supval belonging to the supval of the function at `target`.

        If `target` is ``None`` then use `ea` to locate the function.
        If `value` is ``None``, then remove the supval at the specified `target`.
        """
        node, key = cls.node(), cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._write_header({!r}, {:#x}, {!s}) : Unable to determine the key for target ({!r}) at {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), target, ea))

        # If our key was a list, then we raise an exception because
        # we'd likely overwrite an address with an unrelated header.
        elif isinstance(key, internal.types.list):
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._write_header({!r}, {:#x}, {!s}) : Unable to determine the owner of the address {:#x} as it is owned by {:d} function{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), ea, len(key), '' if len(key) == 1 else 's', ', '.join(map("{:#x}".format, key))))

        # If our header is empty, then we just need to remove the supvalue
        if not value:
            return bool(netnode.sup.remove(node, key))

        try:
            data = cls.marshaller.dumps(value)

        except Exception as E:
            logging.info(u"{:s}._write_header({!r}, {:#x}, {!s}) : Error occurred while marshalling the following data for the cache header: {!r}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), value))
            raise internal.exceptions.SerializationError(u"{:s}._write_header({!r}, {:#x}, {!s}) : Unable to marshal the cache header at address {:#x} for the sup cache associated with key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), ea, key))

        try:
            encdata, sz = cls.codec.encode(data)
            if sz != len(data):
                raise internal.exceptions.SizeMismatchError(u"{:s}._write_header({!r}, {:#x}, {!s}) : The number of bytes that was encoded did not match the expected size ({:#x}<>{:#x}).".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), sz, len(data)))

        except Exception as E:
            logging.warning(u"{:s}._write_header({!r}, {:#x}, {!s}) : An exception {!r} was raised while trying to encode the cache header at address {:#x} for the sup cache associated with key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), E, ea, key), exc_info=True)
            logging.info(u"{:s}._write_header({!r}, {:#x}, {!s}) : Error encoding the following data for the cache header: {!r}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), data))
            raise internal.exceptions.SerializationError(u"{:s}._write_header({!r}, {:#x}, {!s}) : Unable to encode the contents at {:#x} for the sup cache associated with key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), ea, key))

        if len(encdata) > netnode.sup.MAX_SIZE:
            logging.warning(u"{:s}._write_header({!r}, {:#x}, {!s}) : Reached tag limit size ({:#x}>{:#x}) in function with key {:#x}. Possible tag-cache corruption encountered.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), len(encdata), netnode.sup.MAX_SIZE, key))

        ok = netnode.sup.set(node, key, encdata)
        return bool(ok)

    @classmethod
    def _format_netnode_name(cls, target, ea):
        """Return the netnode name for storing a blob in the new format that is associated with the specified `target`.

        If `target` is undefined or ``None`` then use `ea` to locate the function.
        """
        key = cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._format_netnode_name({!r}, {:#x}) : Unable to determine the key for the target ({!r}) at {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, target, ea))

        # If we received a list as the key, then we need to warn the
        # user that we have to guess which supval to read from.
        elif isinstance(key, list):
            key, _ = key[0], logging.critical(u"{:s}._format_netnode_name({!r}, {:#x}) : Choosing to read cache from function {:#x} for address {:#x} as it is owned by {:d} function{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), target, ea, key[0], ea, len(key), '' if len(key) == 1 else 's', ', '.join(map("{:#x}".format, key))))

        # Now we use the function address (key) to generate a unique netnode
        # name by taking the function address and adding the `INF_NETADELTA` to
        # it. Then we go and format the resulting integer by formatting it as
        # hexadecimal and prefixing it with "F". Afterwards, we prefix the whole
        # thing with the netnode name to make the name unique to the plugin.
        Foriginal = functools.partial(operator.add, ida.getinf(idaapi.INF_NETDELTA))
        formatter = "{:s}.{:s}".format(cls.__node__, 'F{:X}')
        return formatter.format(key + ida.getinf(idaapi.INF_NETDELTA))

    @classmethod
    def _move_netnode_tagcache(cls, old, new):
        '''Rename the netnode for the `old` address to the specified `new` address.'''
        oldname = cls._format_netnode_name(old, old)
        newname = cls._format_netnode_name(new, new)

        # First check if the netnode exists with the old name. If it doesn't,
        # then we don't need to move anything at all.
        if not netnode.has(oldname):
            return True

        # Now we can grab the original netnode that we are going to rename.
        # Once we grab it, we then check to see if the new netnode name already
        # exists. If it doesn't, then we can just go ahead and rename. If it
        # does, though, then we extract the tagcache stored for the old name.
        oldnode = netnode.get(oldname)
        if not netnode.has(newname):
            return netnode.name.set(oldnode, newname)
        oldencoded = netnode.blob.get(oldnode, tag=cls.btag)

        # If the new name already exists, then we're going to overwrite its
        # Otherwise, the new name already exists which means we'll be
        # overwriting the contents with the tagcache from the old netnode. We
        # grab the new netnode and also preserve its contents so that we can log
        # exactly what it is we're overwriting.
        newnode = netnode.get(newname)
        newencoded = netnode.blob.get(newnode, tag=cls.btag)

        # Log a warning explaining that we are overwriting the new netnode with
        # the old contents and ensure that the data being overwritten is
        # displayed. Afterwards, we can go ahead and assign the encoded data.
        logging.warning(u"{:s}._move_netnode_tagcache({:#x}, {:#x}) : Overwriting the target netnode \"{!s}\" ({:#x}) using the contents from the source netnode \"{!s}\" ({:#x}).".format('.'.join([__name__, cls.__name__]), old, new, internal.utils.string.escape(newname, '"'), newnode, internal.utils.string.escape(oldname, '"'), oldnode))
        logging.debug(u"{:s}._move_netnode_tagcache({:#x}, {:#x}) : Overwriting the new netnode data in {:#x} ({!s}) using the contents from the old netnode at {:#x} ({!s}).".format('.'.join([__name__, cls.__name__]), old, new, newnode, ''.join(map("{:02x}".format, bytearray(newencoded))), oldnode, ''.join(map("{:02x}".format, bytearray(oldencoded)))))

        if not netnode.blob.set(newnode, tag=cls.btag, value=oldencoded):
            logging.critical(u"{:s}._move_netnode_tagcache({:#x}, {:#x}) : Failure trying to copy {:d} byte{:s} of old tagcache \"{!s}\" ({:#x}) for function {:#x} over {:d} byte{:s} of new tagcache \"{!s}\" ({:#x}) for function {:#x}.".format('.'.join([__name__, cls.__name__]), old, new, len(oldencoded), '' if len(oldencoded) == 1 else 's', internal.utils.string.escape(oldname, '"'), oldnode, old, len(newencoded), '' if len(newencoded) == 1 else 's', internal.utils.string.escape(newname, '"'), newnode, new))

        # Finally, we can remove the netnode containing the old tagcache since
        # it was already copied into the new target netnode.
        ok = netnode.remove(oldnode)
        if not ok:
            logging.warning(u"{:s}._move_netnode_tagcache({:#x}, {:#x}) : Failure trying to remove the netnode \"{!s}\" ({:#x}) containing the tag cache for the old function address ({:#x}).".format('.'.join([__name__, cls.__name__]), old, new, internal.utils.string.escape(oldname, '"'), oldnode, old))
        return ok

    @classmethod
    def _has_old_tagcache(cls, ea):
        '''Return if there is a tagcache in the old format for the function specified by the address `ea`.'''
        key = ea

        # if there is no netnode for the function key, then return false.
        if not netnode.has(key):
            return False

        # if there isn't a blob stored for the functon, then we can just go
        # ahead and return false before doing anything else. otherwise, we
        # extract the data from the blob so that we can check it for bzip2.
        elif not netnode.blob.has(key, tag=cls.btag):
            return False

        # grab the encoded contents of the blob so that we can verify whether it
        # is is bzip2-compressed or not. we need to check for the magic first
        # before verifying that we can actually decompress some of it.
        encoded = netnode.blob.get(key, tag=cls.btag)

        # magic
        bytes = bytearray(encoded)
        if bytes[:3] != b'BZh':
            return False

        # blocksize
        if not (b'1' <= bytes[3 : 4] <= b'9'):
            return False

        # decompress a chunk from the stream
        ok = True
        try:
            dec = bz2.BZ2Decompressor()
            dec.decompress(bytes, max_length=1)
        except (OSError, ValueError):
            ok = False
        return ok

    @classmethod
    def _has_new_tagcache(cls, ea):
        '''Return if there is a tagcache in the new format for the function specified by the address `ea`.'''
        key = ea

        # for performance reasons, we can just format the function address into
        # a name, and then we just need to check if the netnode already exists.
        name = cls._format_netnode_name(key, ea)
        return netnode.has(name)

    @classmethod
    def _get_tagcache_blob(cls, target, ea):
        '''Return the blob for the function at the address specified by `target`.'''
        key = cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._get_tagcache_blob({!r}, {:#x}) : Unable to determine the key for the target ({!r}) at {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, target, ea))

        elif isinstance(key, list):
            key, _ = key[0], logging.critical(u"{:s}._get_tagcache_blob({!r}, {:#x}) : Choosing to read cache from function {:#x} for address {:#x} as it is owned by {:d} function{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), target, ea, key[0], ea, len(key), '' if len(key) == 1 else 's', ', '.join(map("{:#x}".format, key))))

        # check if we're using a specific netnode for the function. otherwise, we
        # need to check if we're using the function's netnode which can be
        # identified by looking for a bzip2-encoded blob. basically, this
        # logic is the gateway to fixing issue #198.
        if cls._has_new_tagcache(key):
            name = cls._format_netnode_name(key, ea)
            return netnode.blob.get(name, tag=cls.btag)

        elif not(cls._has_old_tagcache(key)):
            return None

        # otherwise, we get the blob for the specified function and return it to
        # the caller so that they can decompress and unmarshall it.
        return netnode.blob.get(key, tag=cls.btag)

    @classmethod
    def _new_tagcache_blob(cls, target, ea):
        """Create a tag cache netnode for the function at the address specified by `target`.

        If `target` is undefined or ``None`` then use `ea` to locate the function.
        """
        key = cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._new_tagcache_blob({!r}, {:#x}) : Unable to determine the key for the function containing address {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, ea))

        elif isinstance(key, list):
            key, _ = key[0], logging.critical(u"{:s}._new_tagcache_blob({!r}, {:#x}) : Choosing to read cache from function {:#x} for address {:#x} as it is owned by {:d} function{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), target, ea, key[0], ea, len(key), '' if len(key) == 1 else 's', ', '.join(map("{:#x}".format, key))))

        # figure out the name of the netnode using the key for the function, and
        # check to see if it already exists so that we can avoid creating it.
        name = cls._format_netnode_name(key, ea)
        if netnode.has(name):
            return True

        # now we can use the name to create a new netnode with nothing stashed
        # inside of it. last thing is to return whether we created it or not.
        node = netnode.new(name)
        return netnode.has(node)

    @classmethod
    def _set_tagcache_blob(cls, target, ea, encoded):
        """Update the blob for the function at the address specified by `target` with the given `encoded` data.

        If `target` is undefined or ``None`` then use `ea` to locate the function.
        """
        key = cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._set_tagcache_blob({!r}, {:#x}, {!r}) : Unable to determine the key for the target ({!r}) at {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, encoded, target, ea))

        elif isinstance(key, list):
            key, _ = key[0], logging.critical(u"{:s}._set_tagcache_blob({!r}, {:#x}, {!r}) : Choosing to read cache from function {:#x} for address {:#x} as it is owned by {:d} function{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), target, ea, encoded, key[0], ea, len(key), '' if len(key) == 1 else 's', ', '.join(map("{:#x}".format, key))))

        # if we're using the migrated tagcache already, then go ahead and write
        # to it. this should be what happens by default.
        if cls._has_new_tagcache(key):
            name = cls._format_netnode_name(key, ea)
            node = netnode.get(name)
            return netnode.blob.set(node, tag=cls.btag, value=encoded)

        # otherwise, we just write it to the old location of the tag cache. the
        # tagcache should actually be migrated by someone else. so, that makes
        # this logic a fallback in case that other person didn't migrate it yet.
        return netnode.blob.set(key, tag=cls.btag, value=encoded)

    @classmethod
    def _del_tagcache_blob(cls, target, ea):
        """Remove the blob for the function at the address specified by `target`.

        If `target` is undefined or ``None`` then use `ea` to locate the function.
        """
        key = cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._del_tagcache_blob({!r}, {:#x}) : Unable to determine the key for the target ({!r}) at {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, target, ea))

        elif isinstance(key, list):
            key, _ = key[0], logging.critical(u"{:s}._del_tagcache_blob({!r}, {:#x}) : Choosing to read cache from function {:#x} for address {:#x} as it is owned by {:d} function{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), target, ea, key[0], ea, len(key), '' if len(key) == 1 else 's', ', '.join(map("{:#x}".format, key))))

        # if we're using the migrated tagcache already, then go and erase the
        # bitch. this is intended to switch between the old and new locations.
        if cls._has_new_tagcache(key):
            name = cls._format_netnode_name(key, ea)
            node = netnode.get(name)
            return netnode.blob.remove(node, tag=cls.btag)

        # otherwise, we just remove it from the old location. this should only
        # occur if it hasn't been migrated yet as this location conflicts with
        # some of the disassemblers like AArch and AArch64.
        return netnode.blob.remove(key, tag=cls.btag)

    @classmethod
    def _migrate_tagcache(cls, ea):
        '''Move the tag cache for the function specified by `ea` to its own isolated netnode if it doesn't already exist.'''
        key = ea

        # if we're already using an isolated netnode for the function, then
        # there isn't anything for us to do and we can just return success.
        if cls._has_new_tagcache(key):
            return True

        # if the tag cache is not stashed in the function's netnode, then we
        # don't need to migrate anything. the `contents.has_old_tagcache` method
        # will only return true if the netnode exists and its blob is bzip2'd.
        elif not(cls._has_old_tagcache(key)):
            return True

        # now we go ahead and grab the blob from the old location in the
        # function's netnode, and then we write it to the new location. if the
        # blob is empty, then we create the new netnode but we leave it alone.
        encoded = netnode.blob.get(key, tag=cls.btag)
        if encoded is None:
            return True

        name = cls._format_netnode_name(key, ea)
        node = netnode.new(name)

        ok = netnode.blob.set(node, tag=cls.btag, value=encoded)
        if not ok:
            logging.info(u"{:s}._migrate_tagcache({:#x}) : Error while writing the following data to the blob cache in \"{:s}\" ({:#x}): {!r}.".format('.'.join([__name__, cls.__name__]), ea, internal.utils.string.repr(value), internal.utils.string.escape(name, '"'), node, encoded))
            raise internal.exceptions.DisassemblerError(u"{:s}._migrate_tagcache({:#x}) : Unable to migrate the contents for address {:#x} from the blob cache ({!s}) in the function associated with the key {:#x} to the new netnode \"{:s}\" ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, ea, cls.btag, key, internal.utils.string.escape(name, '"'), node))

        # finally, we go ahead and remove the blob that was previously stashed
        # to the netnode for the specified function.
        ok = netnode.blob.remove(key, tag=cls.btag)
        if not ok:
            logging.warning(u"{:s}._migrate_tagcache({:#x}) : Error while trying to remove the blob data from the tag cache stashed in the function netnode at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, key))
        return ok

    @classmethod
    def _read(cls, target, ea):
        """Reads the value from the contents supval for the specific `target`.

        If `target` is undefined or ``None`` then use `ea` to locate the function.
        """
        node, key = cls.node(), cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._read({!r}, {:#x}) : Unable to determine the key for the target ({!r}) at {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, target, ea))

        # If we received a list as the key, then we need to warn the
        # user that we have to guess which supval to read from.
        elif isinstance(key, internal.types.list):
            key, _ = key[0], logging.critical(u"{:s}._read({!r}, {:#x}) : Choosing to read cache from function {:#x} for address {:#x} as it is owned by {:d} function{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), target, ea, key[0], ea, len(key), '' if len(key) == 1 else 's', ', '.join(map("{:#x}".format, key))))

        # fetch the encoded data from the blob for the function specified by
        # `key` so that we can decode and unmarshal it back into a dictionary.
        encdata = cls._get_tagcache_blob(key, ea)
        if encdata is None:
            return None

        # first we'll decompress the encoded data unless it raises an ecception.
        # if it does, then log what happened and raise the correct exception.
        try:
            data, sz = cls.codec.decode(encdata)
            if len(encdata) != sz:
                raise internal.exceptions.SizeMismatchError(u"{:s}._read({!r}, {:#x}) : The number of bytes that was decoded did not match the expected size ({:#x}<>{:#x}).".format('.'.join([__name__, cls.__name__]), target, ea, sz, len(encdata)))

        except Exception as E:
            logging.warning(u"{:s}._read({!r}, {:#x}) : An exception {!r} was raised while trying to decode the contents for address {:#x} from the blob cache ({!s}) associated with key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, E, ea, cls.btag, key), exc_info=True)
            logging.info(u"{:s}._read({!r}, {:#x}) : Error while decoding the following data from the blob cache: {!r}.".format('.'.join([__name__, cls.__name__]), target, ea, encdata))
            raise internal.exceptions.SerializationError(u"{:s}._read({!r}, {:#x}) : Unable to decode the contents for address {:#x} from the blob cache ({!s}) associated with key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, ea, cls.btag, key))

        # next we'll unmarshall the decompressed data back into a dictionary. if
        # this raises an exception for any reason, then reraise the correct one.
        try:
            result = cls.marshaller.loads(data)

        except Exception as E:
            logging.info(u"{:s}._read({!r}, {:#x}) : Error while unmarshalling the following data from the blob cache: {!r}.".format('.'.join([__name__, cls.__name__]), target, ea, data))
            raise internal.exceptions.SerializationError(u"{:s}._read({!r}, {:#x}) : Unable to unmarshal the contents for address {:#x} from the blob cache ({!s}) associated with key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, ea, cls.btag, key))
        return result

    @classmethod
    def _write(cls, target, ea, value):
        """Writes a `value` to the contents supval for the specific `target`.

        If `target` is undefined or ``None`` then use `ea` to locate the function.
        If `value` is ``None``, then erase the value from the supval.
        """
        node, key = cls.node(), cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to determine the key for target ({!r}) at {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), target, ea))

        # If our key was a list, then we raise an exception instead
        # of just choosing something at random to overwrite.
        elif isinstance(key, internal.types.list):
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to determine the owner of the address {:#x} as it is owned by {:d} function{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), ea, len(key), '' if len(key) == 1 else 's', ', '.join(map("{:#x}".format, key))))

        # check if the blob for our function is stored within its own netnode,
        # so that we can use it. this path should be more efficient.
        if cls._has_new_tagcache(key):
            ok = True

        # if there is no old tagcache, then the blob is empty and we can go
        # ahead and create the blob for the new tagcache.
        elif not cls._has_old_tagcache(key):
            logging.debug(u"{:s}._write({!r}, {:#x}, {!s}) : Creating a netnode for storing the tag cache belonging to function ({:#x}).".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), key))
            ok = cls._new_tagcache_blob(key, ea)

        # otherwise, we need to migrate the tag cache blob from the old location
        # to the new tagcache location. at this point, though, we've already
        # damaged the altvals for the function and there's nothing we can really
        # do to recover the original altvals. :-/
        else:
            logging.debug(u"{:s}._write({!r}, {:#x}, {!s}) : Migrating the tag cache for the specified function ({:#x}) to its own netnode.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), key))
            ok = cls._migrate_tagcache(key)

        # if we couldn't create the netnode for the function to store the tag
        # cache, or we couldn't migrate it from the old location to the new one,
        # then we need to complain about it and abort.
        if not ok:
            name = cls._format_netnode_name(key, ea)
            node = netnode.get(name)
            migrating = cls._has_old_tagcache(key)
            data = " with data ({!s})".format(internal.utils.string.repr(netnode.blob.get(key, tag=cls.btag)))
            logging.info(u"{:s}._write({!r}, {:#x}, {!s}) : Failure while {:s} netnode \"{:s}\" ({:#x}) {!s} for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), 'migrating to' if migrating else 'creating', internal.utils.string.escape(name, '"'), node, data if migrating else '', key))
            raise internal.exceptions.DisassemblerError(u"{:s}._write({!r}, {:#x}, {!s}) : Error while trying to {:s} the tag cache for function {:#x} to an isolated netnode \"{!s}\" ({:#x}).".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), 'migrate' if migrating else 'create', key, internal.utils.string.escape(name, '"'), node))

        # erase cache and blob if no data is specified. we will also be removing
        # the netnode, so we'll start by getting its identifier.
        if not value:
            name = cls._format_netnode_name(key, ea)
            node = netnode.get(name)

            # first we clear the supvalues in the header.
            try:
                ok = cls._write_header(key, ea, None)
                if not ok:
                    logging.debug(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to remove the address {:#x} from the cache header associated with the key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), ea, key))

            # after removing the supvalue in the header for the given function,
            # now we can delete the blob that is stored within the netnode for
            # the function and we should be able to remove the entire netnode.
            finally:
                ok = cls._del_tagcache_blob(key, ea)
                logging.debug(u"{:s}._write({!r}, {:#x}, {!s}) : Removed the blob ({!s}) associated with the key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), cls.btag, key))

                # next we'll try to remove the entire netnode since it's empty.
                if ok:
                    logging.debug(u"{:s}._write({!r}, {:#x}, {!s}) : Attempting to remove the netnode \"{!s}\" ({:#x}) containing the tag cache for function {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), internal.utils.string.escape(name, '"'), node, key))
                    ok = netnode.remove(node)
                    logging.debug(u"{:s}._write({!r}, {:#x}, {!s}) : Removal of netnode \"{!s}\" ({:#x}) from emptying function {:#x} has {!s}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), internal.utils.string.escape(name, '"'), node, key, 'succeeded' if ok else 'failed'))

                ok = ok
            return ok

        # update blob for given address
        res = value
        try:
            data = cls.marshaller.dumps(res)

        except Exception as E:
            logging.info(u"{:s}._write({!r}, {:#x}, {!s}) : Error while unmarshalling the following data for the blob cache: {!r}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), res))
            raise internal.exceptions.SerializationError(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to marshal the contents at address {:#x} for the blob cache ({!s}) associated with key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), ea, cls.btag, key))

        try:
            encdata, sz = cls.codec.encode(data)

        except Exception as E:
            logging.info(u"{:s}._write({!r}, {:#x}, {!s}) : Error encoding the following data for the blob cache: {!r}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), data))
            raise internal.exceptions.SerializationError(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to encode the contents at address {:#x} for the blob cache ({!s}) associated with key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), ea, cls.btag, key))

        if sz != len(data):
            raise internal.exceptions.SizeMismatchError(u"{:s}._write({!r}, {:#x}, {!s}) : The number of bytes that was encoded did not match the expected size ({:#x}<>{:#x}).".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), sz, len(data)))

        # now that we have an encoded version of the data, we can now write the
        # encoded data into the blob for the specified function. we use the
        # classmethod since in order to fix issue #198, so that we store to the
        # correct place if the function tagcache netnode exists. otherwise we
        # fall back to the old (busted) location stored in the function netnode.
        ok = cls._set_tagcache_blob(key, ea, encdata)
        if not ok:
            logging.info(u"{:s}._write({!r}, {:#x}, {!s}) : Error while writing the following data to the blob cache: {!r}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), encdata))
            raise internal.exceptions.DisassemblerError(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to write the contents for address {:#x} to the blob cache ({!s}) associated with the key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), ea, cls.btag, key))

        # update sup cache with keys
        res = {item for item in value.keys()}
        ok = cls._write_header(target, ea, res)
        if not ok:
            raise internal.exceptions.DisassemblerError(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to write the cache header for address {:#x} associated with the key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), ea, key))
        return ok

    @classmethod
    def iterate(cls):
        '''Yield each address and names for all of the contents tags in the database according to what is written into the tagging supval.'''
        node = cls.node()
        for ea in netnode.sup.fiter(node):
            view = netnode.sup.get(node, ea, type=memoryview)
            encdata = view.tobytes()
            data, sz = cls.codec.decode(encdata)
            if len(encdata) != sz:
                logging.warning(u"{:s}.iterate() : Error while decoding the tag names out of the sup cache for address {:#x} due to the length of encoded data not matching the expected size ({:#x}<>{:#x}).".format('.'.join([__name__, cls.__name__]), ea, len(encdata), sz))
            res = cls.marshaller.loads(data)
            yield ea, res
        return

    # FIXME: the next 4 functions are a hack in order to facilitate bulk updates
    #        of the addresses in the contents of a function. this means things
    #        like translating the addresses to a different base address. these
    #        four functions should really be combined into a single one that
    #        allows translating the addresses and writing them to the netnode of
    #        a completely different function.

    @classmethod
    def function(cls, target, address):
        '''Yield the address and reference count for every contents address in the function `target`.'''
        key = address if target is None else target
        items = cls._read(key, address)
        if items is None:
            return
        return {ea : count for ea, count in items.get(cls.__address__, {}).items()}

    @classmethod
    def setfunction(cls, target, address, new):
        '''Set the address and reference count for every address in the function `target` to `new`.'''
        state = cls._read(target, address) or {}

        # extract the address dictionary from the read state, and update it with
        # the dictionary that we were given. the purpose of this function is to
        # update the contents addresses for a function in bulk.
        res, state[cls.__address__] = state.get(cls.__address__, {}), new

        # attempt to write the modified state back where we had gotten it from.
        if internal.tagcache.contents._write(target, address, state):
            return res
        return

    @classmethod
    def functiontags(cls, target, address):
        '''Yield the address and reference count for every contents address in the function `target`.'''
        key = address if target is None else target
        items = cls._read(key, address)
        if items is None:
            return
        return {tag : count for tag, count in items.get(cls.__tags__, {}).items()}

    @classmethod
    def setfunctiontags(cls, target, address, new):
        '''Set the tag and reference count for every tag in the function `target` to `new`.'''
        state = cls._read(target, address) or {}

        # extract the address dictionary from the read state, and update it with
        # the dictionary that we were given. the purpose of this function is to
        # update the contents addresses for a function in bulk.
        res, state[cls.__tags__] = state.get(cls.__tags__, {}), new

        # attempt to write the modified state back where we had gotten it from.
        if internal.tagcache.contents._write(target, address, state):
            return res
        return

    # ...and now, back to our regularly scheduled programming.

    @classmethod
    def inc(cls, address, name, **target):
        """Increase the ref count for the given `address` and `name` belonging to the function `target`.

        If `target` is undefined or ``None`` then use `address` to locate the function.
        """
        # If we weren't given a target, then we need to figure the key out ourselves.
        if target.get('target', None) is None:
            res = cls._key(address)
            keys = res if isinstance(res, internal.types.list) else [res]

        # If we were given a valid target, then turn it into a list unless it already is.
        else:
            keys = target['target'] if isinstance(target['target'], internal.types.list) else [target['target']]

        # Now we just iterate through all of the keys and update the cache.
        result = 0
        for key in keys:
            item = cls._read(key, address) or {}
            state, cache = item.get(cls.__tags__, {}), item.get(cls.__address__, {})

            # Update the reference count for the items we were given.
            state[name] = refs = state.get(name, 0) + 1
            cache[address] = cache.get(address, 0) + 1

            # Figure out whether we're removing the entry for the tags or adding it.
            if state: item[cls.__tags__] = state
            else: del item[cls.__tags__]

            # Now do the exact same thing for the address.
            if cache: item[cls.__address__] = cache
            else: del item[cls.__address__]

            # Now we can write that shit back into the cache.
            _, result = cls._write(key, address, item), result + refs
        return result

    @classmethod
    def dec(cls, address, name, **target):
        """Decreate the ref count for the given `address` and `name` belonging to the function `target`.

        If `target` is undefined or ``None`` then use `address` to locate the function.
        """
        # If we were asked to figure the target out ourselves, then do as we're told.
        if target.get('target', None) is None:
            res = cls._key(address)
            keys = res if isinstance(res, internal.types.list) else [res]

        # Otherwise turn what we were given into a list unless it already was.
        else:
            keys = target['target'] if isinstance(target['target'], internal.types.list) else [target['target']]

        # Now we can just iterate through all of the keys to update each cache.
        result = 0
        for key in keys:
            item = cls._read(key, address) or {}
            state, cache = item.get(cls.__tags__, {}), item.get(cls.__address__, {})

            # Pop the number of references and the count of addresses and adjust
            # them. We pop them because if the reference count drops below its
            # minimum, then we remove the tag so that we can detect when the
            # index has been decremented past what's available.
            refs, count = state.pop(name, 0) - 1, cache.pop(address, 0) - 1

            # If we still have some references for the names and the addresses,
            # then add our keys back into the state and cache.
            if refs > 0: state[name] = refs
            if count > 0: cache[address] = count

            # Figure out whether we're removing the names or keeping them.
            if state: item[cls.__tags__] = state
            else: item.pop(cls.__tags__, None)

            # We do the exact same thing for the address reference count.
            if cache: item[cls.__address__] = cache
            else: item.pop(cls.__address__, None)

            # We can finally write our reference counts back to the current key.
            _, result = cls._write(key, address, item), result + refs
        return result

    @classmethod
    def name(cls, address, **target):
        """Return all the tag names (``set``) for the contents of the function `target`.

        If `target` is undefined or ``None`` then use `address` to locate the function.
        """
        key = target.get('target', None)
        res = cls._read(key, address) or {}
        res = res.get(cls.__tags__, {})
        return {item for item in res.keys()}

    @classmethod
    def counts(cls, address, **target):
        """Yield each tag name and its count for the contents of the function `target`.

        If `target` is undefined or ``None`` then use `address` to locate the function.
        """
        key = target.get('target', None)
        items = cls._read(key, address) or {}
        for tag, count in items.get(cls.__tags__, {}).items():
            yield tag, count
        return

    @classmethod
    def address(cls, address, **target):
        """Return all the addresses (``sorted``) with tags in the contents for the function `target`.

        If `target` is undefined or ``None`` then use `address` to locate the function.
        """
        key = target.get('target', None)
        res = cls._read(key, address) or {}
        res = res.get(cls.__address__, {})
        return sorted(res.keys())

    @classmethod
    def erase(cls, ea):
        '''Remove the contents of the function at the address `ea`.'''
        target = ea if netnode.blob.has(ea, index=0, tag=cls.btag) else cls._key(ea)
        if not target:
            raise internal.exceptions.DisassemblerError(u"{:s}.erase({:#x}) : Unable to determine the key from function address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, ea))

        result = cls._read(target, ea)
        if not cls._write(target, ea, None):
            raise internal.exceptions.DisassemblerError(u"{:s}.erase({:#x}) : Unable to erase the cache header for function address {:#x} associated with the key {:#x}.".format('.'.join([__name__, cls.__name__]), ea, ea, target))
        return result

    @classmethod
    def erase_address(cls, target, ea):
        '''Remove the tags at the address `ea` from the contents of the function `target`.'''
        fn = target if target is not None else ea if netnode.blob.has(ea, index=0, tag=cls.btag) else cls._key(ea)
        if not fn:
            target_description = "{:#x}".format(target) if isinstance(target, internal.types.integer) else "{!s}".format(target)
            address_description = "{:#x}".format(ea) if target is None else "{:#x}".format(target)
            raise internal.exceptions.DisassemblerError(u"{:s}.erase_address({!s}, {:#x}) : Unable to determine the key from function address {:#x}.".format('.'.join([__name__, cls.__name__]), target_description, ea, address_description))

        # read the header contents and then set the reference count for the
        # chosen address to 0. remove any dictionaries that are empty.
        result = cls._read(fn, ea)

        newresult = {key : value.copy() for key, value in result.items()}
        newresult[cls.__address__].pop(ea, 0)
        newresult[cls.__address__] or newresult.pop(cls.__address__, {})

        # write the modified header back into where we got it from.
        if not cls._write(fn, ea, newresult):
            target_description = "{:#x}".format(target) if isinstance(target, internal.types.integer) else "{!s}".format(target)
            address_description = "{:#x}".format(ea) if target is None else "{:#x}".format(target)
            raise internal.exceptions.DisassemblerError(u"{:s}.erase_address({!s}, {:#x}) : Unable to erase the cache header for function address {:#x} associated with the key {:#x}.".format('.'.join([__name__, cls.__name__]), target_description, ea, address_description, fn))
        return result

    @classmethod
    def destroy(cls, ea):
        '''Destroy the contents associated with the function at address `ea`.'''
        node, key = tagging.node(), cls._key(ea)
        ok_sup = netnode.sup.remove(node, key)
        ok_blob = internal.netnode.blob.remove(key, tag=cls.btag, index=0)
        return ok_sup and ok_blob

    @classmethod
    def set_name(cls, address, name, count, **target):
        """Set the contents tag count for the function `target` and `name` to `count`.

        If `target` is undefined or ``None`` then use `address` to locate the function.
        """
        key = target.get('target', None)
        state = cls._read(key, address) or {}

        res = state.get(cls.__tags__, {})
        if count > 0:
            res[name] = count
        else:
            res.pop(name, None)

        if res:
            state[cls.__tags__] = res
        else:
            state.pop(cls.__tags__, None)

        try:
            ok = cls._write(key, address, state)
            if ok:
                return state
        except Exception as E:
            logging.warning(u"{:s}.set_name({:#x}, {!r}, {:d}{:s}) : An exception {!r} was raised while trying to update the name cache for address {:#x}.".format('.'.join([__name__, cls.__name__]), address, name, count, ', {:s}'.format(internal.utils.string.kwargs(target)) if target else '', E, address), exc_info=True)
        raise internal.exceptions.ReadOrWriteError(u"{:s}.set_name({:#x}, {!r}, {:d}{:s}) : Unable to update the name cache for address {:#x}.".format('.'.join([__name__, cls.__name__]), address, name, count, ', {:s}'.format(internal.utils.string.kwargs(target)) if target else '', address))

    @classmethod
    def set_address(cls, address, count, **target):
        """Set the contents tag count for the function `target` and `address` to `count`.

        If `target` is undefined or ``None`` then use `address` to locate the function.
        """
        key = target.get('target', None)
        state = cls._read(key, address) or {}

        res = state.get(cls.__address__, {})
        if count > 0:
            res[address] = count
        else:
            res.pop(address, None)

        if res:
            state[cls.__address__] = res
        else:
            state.pop(cls.__address__, None)

        try:
            ok = cls._write(key, address, state)
            if ok:
                return state
        except Exception as E:
            logging.warning(u"{:s}.set_address({:#x}, {:d}{:s}) : An exception {!r} was raised while trying to update the cache for address {:#x}.".format('.'.join([__name__, cls.__name__]), address, count, ', {:s}'.format(internal.utils.string.kwargs(target)) if target else '', E, address), exc_info=True)
        raise internal.exceptions.ReadOrWriteError(u"{:s}.set_address({:#x}, {:d}{:s}) : Unable to write to the cache for address {:#x}.".format('.'.join([__name__, cls.__name__]), address, count, ', {:s}'.format(internal.utils.string.kwargs(target)) if target else '', address))

class globals(tagging):
    """
    This namespace is used to update the tag state for all the globals in
    the database. Each global tag has its target address and its name and
    is managed by keeping track of a reference count.

    The reference count is stored within a netnode as defined by
    `tagging.node()`. The refcount for each address containing a
    tag is stored in an altval keyed by the address. The refcount
    for each tag name is stored in a hashval keyed by the tags
    name.
    """

    # netnode.alt[address] = refcount
    # netnode.hash[name] = refcount

    @classmethod
    def inc(cls, address, name):
        '''Increase the global tag count for the given `address` and `name`.'''
        node, eName = cls.node(), internal.utils.string.to(name)

        cName = (netnode.hash.get(node, eName, type=int) or 0) + 1
        cAddress = (netnode.alt.get(node, address) or 0) + 1

        netnode.hash.set(node, eName, cName)
        netnode.alt.set(node, address, cAddress)

        return cName

    @classmethod
    def dec(cls, address, name):
        '''Decrease the global tag count for the given `address` and `name`.'''
        node, eName = cls.node(), internal.utils.string.to(name)

        cName = (netnode.hash.get(node, eName, type=int) or 1) - 1
        cAddress = (netnode.alt.get(node, address) or 1) - 1

        if cName < 1:
            netnode.hash.remove(node, eName)
        else:
            netnode.hash.set(node, eName, cName)

        if cAddress < 1:
            netnode.alt.remove(node, address)
        else:
            netnode.alt.set(node, address, cAddress)

        return cName

    @classmethod
    def name(cls):
        '''Return all the tag names (``set``) in the specified database (globals and func-tags)'''
        node = cls.node()
        iterable = (internal.utils.string.of(name) for name in netnode.hash.fiter(node))
        return {(name if isinstance(name, internal.types.string) else name.decode('utf-8')) for name in netnode.hash.fiter(node)}

    @classmethod
    def address(cls):
        '''Return all the tag addresses in the specified database (globals and func-tags)'''
        return netnode.alt.fiter(cls.node())

    @classmethod
    def erase(cls, address):
        '''Remove the reference count for the global tags at the specified `address`.'''
        Fget_tags = internal.tags.function.get if idaapi.get_func(address) else internal.tags.address.get
        tags = {tag for tag in Fget_tags(address)}
        [cls.dec(address, tag) for tag in tags]
        count = cls.set_address(address, 0)
        if count:
            logging.debug(u"{:s}.erase({:#x}) : Erasing the tags at global address {:#x} results in an unexpected reference count ({:d}).".format('.'.join([__name__, cls.__name__]), address, address, count))
        return count

    @classmethod
    def destroy(cls, *address):
        '''Destroy the tags for the specified global `address` in the database.'''
        node = tagging.node()
        if address:
            return internal.netnode.alt.remove(node, *address)

        alts = [ea for ea in netnode.alt.fiter(node)]
        for idx, ea in enumerate(alts):
            internal.netnode.alt.remove(node, ea)
        return True

    @classmethod
    def destroy_tag(cls, *name):
        '''Destroy the tag with the specified `name`.'''
        node = tagging.node()
        if name:
            return internal.netnode.hash.remove(node, *name)

        hashes = [item for item in netnode.hash.fiter(node)]
        for idx, tag in enumerate(hashes):
            internal.netnode.hash.remove(node, tag)
        return True

    @classmethod
    def set_name(cls, name, count):
        '''Set the global tag count for `name` in the database to `count`.'''
        node, eName = cls.node(), internal.utils.string.to(name)
        res = netnode.hash.get(node, eName, type=int)
        netnode.hash.set(node, eName, count)
        return res

    @classmethod
    def set_address(cls, address, count):
        '''Set the global tag count for `address` in the database to `count`.'''
        node = cls.node()
        res = netnode.alt.get(node, address)
        netnode.alt.set(node, address, count)
        return res

    @classmethod
    def iterate(cls):
        '''Yield the address and count for each of the globals in the database according to what is written in the altvals.'''
        node = cls.node()
        for ea, count in netnode.alt.fitems(node):
            yield ea, count
        return

    @classmethod
    def counts(cls):
        '''Yield the tag name and its count for each of the globals in the database according to what is written in the hashvals.'''
        node = cls.node()

        for item, count in netnode.hash.fitems(node, int):
            string = internal.utils.string.of(item)
            name = string if isinstance(string, internal.types.string) else string.decode('utf-8')
            yield name, count
        return
