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

import idaapi, internal, logging
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
        node, key = tagging.node(), cls._key(ea) if target is None else target
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
        node, key = tagging.node(), cls._key(ea) if target is None else target
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
    def _read(cls, target, ea):
        """Reads the value from the contents supval for the specific `target`.

        If `target` is undefined or ``None`` then use `ea` to locate the function.
        """
        node, key = tagging.node(), cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._read({!r}, {:#x}) : Unable to determine the key for the target ({!r}) at {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, target, ea))

        # If we received a list as the key, then we need to warn the
        # user that we have to guess which supval to read from.
        elif isinstance(key, internal.types.list):
            key, _ = key[0], logging.critical(u"{:s}._read({!r}, {:#x}) : Choosing to read cache from function {:#x} for address {:#x} as it is owned by {:d} function{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), target, ea, key[0], ea, len(key), '' if len(key) == 1 else 's', ', '.join(map("{:#x}".format, key))))

        encdata = netnode.blob.get(key, tag=cls.btag, index=0)
        if encdata is None:
            return None

        try:
            data, sz = cls.codec.decode(encdata)
            if len(encdata) != sz:
                raise internal.exceptions.SizeMismatchError(u"{:s}._read({!r}, {:#x}) : The number of bytes that was decoded did not match the expected size ({:#x}<>{:#x}).".format('.'.join([__name__, cls.__name__]), target, ea, sz, len(encdata)))

        except Exception as E:
            logging.warning(u"{:s}._read({!r}, {:#x}) : An exception {!r} was raised while trying to decode the contents for address {:#x} from the blob cache ({!s}) associated with key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, E, ea, cls.btag, key), exc_info=True)
            logging.info(u"{:s}._read({!r}, {:#x}) : Error while decoding the following data from the blob cache: {!r}.".format('.'.join([__name__, cls.__name__]), target, ea, encdata))
            raise internal.exceptions.SerializationError(u"{:s}._read({!r}, {:#x}) : Unable to decode the contents for address {:#x} from the blob cache ({!s}) associated with key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, ea, cls.btag, key))

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
        node, key = tagging.node(), cls._key(ea) if target is None else target
        if key is None:
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to determine the key for target ({!r}) at {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), target, ea))

        # If our key was a list, then we raise an exception instead
        # of just choosing something at random to overwrite.
        elif isinstance(key, internal.types.list):
            raise internal.exceptions.FunctionNotFoundError(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to determine the owner of the address {:#x} as it is owned by {:d} function{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), ea, len(key), '' if len(key) == 1 else 's', ', '.join(map("{:#x}".format, key))))

        # erase cache and blob if no data is specified
        if not value:
            try:
                ok = cls._write_header(target, ea, None)
                if not ok:
                    logging.debug(u"{:s}._write({!r}, {:#x}, {!s}) : Unable to remove the address {:#x} from the cache header associated with the key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), ea, key))

            finally:
                count = netnode.blob.remove(key, tag=cls.btag, index=0)
                logging.debug(u"{:s}._write({!r}, {:#x}, {!s}) : Removed {:d} blob{:s} ({!s}) associated with the key {:#x}.".format('.'.join([__name__, cls.__name__]), target, ea, internal.utils.string.repr(value), count, '' if count == 1 else 's', cls.btag, key))

            return True

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

        # write blob
        ok = netnode.blob.set(key, tag=cls.btag, value=encdata, index=0)
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
        node = tagging.node()
        for ea in netnode.sup.fiter(node):
            view = netnode.sup.get(node, ea, type=memoryview)
            encdata = view.tobytes()
            data, sz = cls.codec.decode(encdata)
            if len(encdata) != sz:
                logging.warning(u"{:s}.iterate() : Error while decoding the tag names out of the sup cache for address {:#x} due to the length of encoded data not matching the expected size ({:#x}<>{:#x}).".format('.'.join([__name__, cls.__name__]), ea, len(encdata), sz))
            res = cls.marshaller.loads(data)
            yield ea, res
        return

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
        node, eName = tagging.node(), internal.utils.string.to(name)

        cName = (netnode.hash.get(node, eName, type=int) or 0) + 1
        cAddress = (netnode.alt.get(node, address) or 0) + 1

        netnode.hash.set(node, eName, cName)
        netnode.alt.set(node, address, cAddress)

        return cName

    @classmethod
    def dec(cls, address, name):
        '''Decrease the global tag count for the given `address` and `name`.'''
        node, eName = tagging.node(), internal.utils.string.to(name)

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
        node = tagging.node()
        iterable = (internal.utils.string.of(name) for name in netnode.hash.fiter(node))
        return {(name if isinstance(name, internal.types.string) else name.decode('utf-8')) for name in netnode.hash.fiter(node)}

    @classmethod
    def address(cls):
        '''Return all the tag addresses in the specified database (globals and func-tags)'''
        return netnode.alt.fiter(tagging.node())

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
        node, eName = tagging.node(), internal.utils.string.to(name)
        res = netnode.hash.get(node, eName, type=int)
        netnode.hash.set(node, eName, count)
        return res

    @classmethod
    def set_address(cls, address, count):
        '''Set the global tag count for `address` in the database to `count`.'''
        node = tagging.node()
        res = netnode.alt.get(node, address)
        netnode.alt.set(node, address, count)
        return res

    @classmethod
    def iterate(cls):
        '''Yield the address and count for each of the globals in the database according to what is written in the altvals.'''
        node = tagging.node()
        for ea, count in netnode.alt.fitems(node):
            yield ea, count
        return

    @classmethod
    def counts(cls):
        '''Yield the tag name and its count for each of the globals in the database according to what is written in the hashvals.'''
        node = tagging.node()

        for item, count in netnode.hash.fitems(node, int):
            string = internal.utils.string.of(item)
            yield string.decode('utf-8'), count
        return
