import six, functools, operator, logging, string, array, collections
import internal, idaapi

SECTOR = 1024
INTEGER_SIZE = 8

class namedtypedtuple(tuple):
    """
    A named tuple with actual type checking.
    """
    _fields = ()
    _types = ()

    def __new__(cls, *args):
        '''Construct a new instance of a tuple using the specified `args`.'''
        res = args[:]
        for n, t, x in zip(cls._fields, cls._types, args):
            if not isinstance(x, t):
                raise TypeError("Unexpected type ({!r}) for field {:s} should be {!r}.".format(type(x), n.encode('utf8') if isinstance(n, unicode) else n, t))
            continue
        return tuple.__new__(cls, res)

    @classmethod
    def _make(cls, iterable, cons=tuple.__new__, len=len):
        """Make a tuple using the values specified in `iterable`.

        If `cons` is specified as a callable, then use it to construct the type.
        If `len` is specified as a callable, then use it to return the length.
        """
        result = cons(cls, iterable)
        if len(result) != len(cls._fields):
            raise TypeError("Expected {:d} arguments, got {:d}.".format(len(cls._fields), len(result)))
        for n, t, x in zip(cls._fields, cls._types, result):
            if not isinstance(x, t):
                raise TypeError("Unexpected type ({!r} for field {:s} should be {!r}.".format(type(x), n.encode('utf8') if isinstance(n, unicode) else n, t))
            continue
        return result

    @classmethod
    def _type(cls, name):
        '''Return the type for the field `name`.'''
        res = (t for n, t in zip(cls._fields, cls._types) if n == name)
        try:
            result = six.next(res)
        except StopIteration:
            raise NameError("Unable to locate the type for an unknown field {!r}.".format(name))
        return result

    def __getattribute__(self, name):
        try:
            # honor the ._fields first
            res = object.__getattribute__(self, '_fields')
            res = map(operator.methodcaller('lower'), res)
            res = operator.itemgetter(res.index(name.lower()))
        except (IndexError, ValueError):
            res = lambda s: object.__getattribute__(s, name)
        return res(self)

    def __repr__(self):
        cls = self.__class__
        res = ("{!s}={!s}".format(internal.utils.string.escape(name, ''), internal.utils.string.repr(value)) for name, value in zip(self._fields, self))
        return "{:s}({:s})".format(cls.__name__, ', '.join(res))

    def _replace(self, **fields):
        '''Assign the specified `fields` to the fields within the tuple.'''
        fc = fields.copy()
        result = self._make(map(fc.pop, self._fields, self))
        if fc:
            cls = self.__class__
            logging.warn(u"{:s}._replace({:s}) : Unable to assign unknown field names ({:s}) to tuple.".format('.'.join(('internal', __name__, cls.__name__)), internal.utils.string.kwargs(fields), '{' + ', '.join(map(internal.utils.string.repr, six.viewkeys(fc))) + '}'))
        return result
    def _asdict(self): return collections.OrderedDict(zip(self._fields, self))
    def __getnewargs__(self): return tuple(self)
    def __getstate__(self): return tuple(self)

class position(namedtypedtuple):
    _fields = 'sector', 'offset'
    _types = six.integer_types, six.integer_types

    @classmethod
    def new(cls, position):
        sector = position // SECTOR
        offset = position & (SECTOR - 1)
        return cls(sector, offset)

    @classmethod
    def size(self):
        return 2 * INTEGER_SIZE

    @classmethod
    def ofbytes(cls, data):
        typecode = internal.utils.get_array_typecode(INTEGER_SIZE)
        res = array.array(typecode)
        res.fromstring(data)
        return cls(*res)

    def tobytes(self):
        typecode = internal.utils.get_array_typecode(INTEGER_SIZE)
        res = array.array(typecode, self)
        return memoryview(buffer(res)).tobytes()

    def int(self):
        sector, offset = self
        return sector * SECTOR + offset

class index_item(namedtypedtuple):
    _fields = 'position', 'content', 'name'
    _types = position, six.integer_types, six.integer_types

    @classmethod
    def size(self):
        return position.size() + 2 * INTEGER_SIZE

    @classmethod
    def ofbytes(cls, data):
        typecode = internal.utils.get_array_typecode(INTEGER_SIZE)
        res = array.array(typecode)
        res.fromstring(data)
        return cls(position(*res[:2].tolist()), *res[2:].tolist())

    def tobytes(self):
        position, name, content = self
        typecode = internal.utils.get_array_typecode(INTEGER_SIZE)
        res = array.array(typecode, [name, content])
        return position.tobytes() + memoryview(buffer(res)).tobytes()

class Index(object):
    """
    This class is responsible for reading the filesystem index from a
    netnode in the database, and then loading its contents. It can
    mostly be treated as a dictionary where each value is a tuple of
    the type `content_item`.
    """
    itag, __node__ = six.byte2int(b'I'), '$ filesystem.index'

    def __init__(self):
        # Try and fetch our netnode first. If we can't then we need to
        # create it and use that one instead.
        res = internal.netnode.get(self.__node__)
        if res == idaapi.BADADDR:
            res = internal.netnode.new(self.__node__)
        self.__cache_id__ = res

        # This dict mirrors all of indices of the `_table` but contains any
        # any attributes that need to be synchronized to the netnode due
        # to either a name or contents change.
        self._dirty = {}

        # First we'll need to read the index out of our netnode.
        self._index = index = self.__read_index__()

        # Then we need to read our name-table and content for file.
        self._table = table = self.__read_table__(index)

        # Now we'll build the actual lookup-table which will map a name
        # to an index within our table.
        self._cache = { name : index for index, (_, _, name, _) in enumerate(table) }

    def __read_index__(self):
        '''Read the current index directly from the blob associated with the netnode.'''
        cls = self.__class__

        # Read the number of items that we'll need to load.
        icount = internal.netnode.blob.size(self.__cache_id__, Index.itag)
        count = icount // index_item.size()
        logging.info("{:s}.__read_index__({:#x}): Found {:d} items in index of size {:+d}.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, count, icount))

        # Read the actual blob data that contains our index, and then
        # chunk it out by each item's size.
        data = internal.netnode.blob.get(self.__cache_id__, Index.itag) or b''
        idata = iter(bytearray(data))
        items = [bytes().join(map(six.int2byte, item)) for item in zip(*[iter(idata)] * index_item.size())]

        # Validate that the number of items match the count that we expect,
        # and proceed to deserialize them in order to get our index.
        if len(items) != count:
            raise ValueError("{:s}.__read_index__({:#x}): Read {:d} items, but expected {:d} items in index.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, len(items), count))

        return [ index_item.ofbytes(item) for item in items ]

    def __read_table__(self, index):
        '''Read the name table using the list provided by `index`.'''
        cls = self.__class__

        # Create a sector-cache so that we don't have to double-read
        # anything that we've already read.
        cache = {}

        # Iterate through our entire index so that we can actually
        # read the contents of each entry.
        result = []
        for i, entry in enumerate(index):
            position, contentsz, namesz = entry

            # Figure out how many slots in our cache that will end
            # up being used.
            totalsz = namesz + contentsz
            logging.info("{:s}.__read_table__({:#x}): Found entry #{:d} in index with name ({:d}) and contents ({:d}) with a total of {:d} bytes.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, i, namesz, contentsz, totalsz))

            # Now to try and fetch our blocks of data. If it's not
            # found in our cache, then we need to read them from the
            # netnode's supval.
            items = []
            for si in range(position.sector, position.sector + (position.offset + totalsz + SECTOR - 1) // SECTOR):
                item = cache.setdefault(si, bytearray(internal.netnode.sup.get(self.__cache_id__, si) or b''))
                items.append(item)

            # Join our data together, and then chop out the segment
            # that contains our two components.
            data = functools.reduce(operator.add, items, bytearray())[position.offset:]
            econtent, ename = map(bytes, [data[:contentsz], data[contentsz : contentsz + namesz]])

            # First we'll need to unmarshal the content (content_item),
            # because if we can't decode this then we won't be able to
            # even find our file contents.
            try:
                content = content_item.ofbytes(econtent)

            # If we got an error decoding the content then we need to bail.
            except Exception as E:
                logging.fatal("{:s}.__read_table__({:#x}): Unable to load content for item #{:d} from index.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, i), exc_info=True)
                continue

            # Now to decode our name, unmarshal the content, and then
            # add it to our result list.
            try:
                name = ename.decode('utf-8')

            # If we got an error decoding the name, then fall back to using
            # the index.
            except Exception as E:
                name = "{:d}".format(i)
                logging.warn("{:s}.__read_table__({:#x}): Unable to decode name for item #{:d} from index. Using its index ({!s}) as the name.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, i, name), exc_info=True)

            # Then finally add it to our result list.
            logging.info("{:s}.__read_table__({:#x}): Added entry #{:d} at {!s} with name ({!r}).".format('.'.join([__name__, cls.__name__]), self.__cache_id__, i, position, name))
            result.append((position, i, name, content))

        # Last thing we need to do is to now sort our list of items
        # by their position so that we can do a heapsearch when
        # looking for holes to fill up.
        return sorted(result, key=operator.itemgetter(0))

    def __iter__(self):
        '''Iterate through all of the names within the Index.'''
        for name in self._cache:
            yield name
        return

    def __getitem__(self, name):
        '''Return the content-item in the Index associated with the specified `name`.'''
        index = self.find(name)
        _, _, _, item = self.get(index)
        return item

    def __setitem__(self, name, content):
        '''Assign the specified `content` to the provided `name` in the Index.'''
        index = self.find(name)
        return self.set(index, content)

    def __repr__(self):
        result = [object.__repr__(self.__class__)]

        # Aggregate all changes within the current table.
        used = {item for item in []}
        for idx, (pos, _, name, content) in enumerate(self._table):
            name_s = name if all(operator.contains(string.printable, ch) for ch in name) else "{!r}".format(name)
            if operator.contains(self._dirty, idx):
                _, _, newname, newcontent = self._dirty[idx]
                newname_s = newname if all(operator.contains(string.printable, ch) for ch in name) else "{!r}".format(newname)
                namecomponent = "{!s}".format(name_s) if name == newname else "{!s} -> {!s}".format(name_s, newname_s)
                contentcomponent = "{!s}".format(content) if content == newcontent else "{!s} -> {!s}".format(content, newcontent)
                result.append("(dirty) {:s} : {:s}".format(namecomponent, contentcomponent))
            else:
                result.append("{!s} : {!s}".format(name_s, content))

            # Collect the index that we've just used.
            used.add(idx)

        # Go through our dirty cache, and aggregate everything that's new.
        for idx in six.viewkeys(self._dirty) - used:
            _, _, newname, newcontent = self._dirty[idx]
            newname_s = newname if all(operator.contains(string.printable, ch) for ch in name) else "{!r}".format(newname)
            result.append("(new) {!s} : {!s}".format(newname_s, newcontent))

        return '\n'.join(result)

    def find(self, name):
        '''Return the index in the table for the specified `name`.'''
        return self._cache[name]

    def get(self, index):
        '''Return the table entry for the specified `index`.'''
        if operator.contains(self._dirty, index):
            return self._dirty[index]
        return self._table[index]

    def rename(self, name, newname):
        '''Rename of the entry for `name` in the Index to `newname`.'''
        index = self.find(name)
        return self._rename(index, newname)

    def _rename(self, index, newname):
        '''Modify the name of the table entry at `index` to `newname`.'''
        position, i, name, content = self.get(index)

        # If the newname is valid, then update the name in the dirty cache
        if len(newname) > 0:
            self._dirty[index] = position, i, newname, content

            # We also need to update the cache so the newname can be
            # used to look up things.
            self._cache[newname] = self._cache.pop(name)
            return index

        raise ValueError(newname)

    def set(self, index, item):
        '''Modify the contents of the table entry at `index` to `item`.'''
        if not isinstance(item, content_item):
            raise TypeError(item)
        position, i, name, content = self.get(index)

        # All we need to do is mark the entry as dirty, and then update
        # the table with the new content_item
        self._dirty[index] = position, i, name, item
        return index

    def add(self, name, item):
        '''Add the contents in `item` to the Index for the specified `name`.'''
        if not isinstance(name, six.string_types):
            raise TypeError(name)
        if not isinstance(item, content_item):
            raise TypeError(item)

        # Check if the name is a duplicate so we can complain.
        if operator.contains(self._cache, name):
            raise KeyError(name)

        # Figure out what the next index should likely be.
        index = max(len(self._table), 1 + max([index for index in self._dirty]) if self._dirty else 0)

        # Now we need to update our dirty cache for the index.
        self._dirty[index] = None, index, name, item
        self._cache[name] = index
        return index

    def remove(self, name):
        '''Remove the specified `name` from the Index.'''
        index = self.find(name)
        return self._remove(index)

    def _remove(self, index):
        '''Remove the table entry at `index`.'''
        position, i, name, content = self._table[index]

        # If our name is empty, then that means that the entry will need
        # to be removed during update.
        self._dirty[index] = position, i, '', content

        # Remove the name from the cache
        return self._cache.pop(name)

    def __build_entire_cache__(self):
        '''Re-construct the entire index using the table.'''
        result = []
        for position, _, name, content in self._table:
            result.append((position, name, content))

        # Go through the dirty cache and update our result with its values
        for index in sorted(self._dirty):
            position, _, name, content = self._dirty[index]
            if index < len(result):
                result[index] = position, name, content
            else:
                result.append((position, name, content))
            continue

        # We promised a rebuild, so re-create our entire table here
        return { index : item for index, item in enumerate(result) }

    def __build_dirty_cache__(self):
        '''Build a lookup table containing only the dirty entries.'''
        result = {}
        for index, item in self._dirty.items():
            position, _, name, content = item
            if operator.contains(self._dirty, index):
                position, _, name, content = self._dirty[index]
                result[index] = position, name, content
            continue
        return result

    @classmethod
    def __find_free_blocks__(cls, index, update):
        '''Return a dict of lists containing all available positions in `index`.'''
        result = {}

        # First go through our updates and gather all open slots that are from
        # an object being removed.
        for i, (pos, name, content) in update.items():
            if pos and len(name) == 0:
                _, namesz, contentsz = index[i]
                result.setdefault(namesz + contentsz, []).append(pos)
            continue

        # Go through the index, gather all the boundaries.
        bounds = []
        for i, (pos, namesz, contentsz) in enumerate(index):
            bounds.append((pos.int(), namesz + contentsz))

        # Now we need to sort them and prefix them with an empty boundary (0,0)
        # so that we can grab any slack-space at the beginning
        bounds = [(0, 0)] + sorted(bounds, key=operator.itemgetter(0))

        # Now that we've figured out our boundaries from the index, go
        # through and determine whether there's any free space we can reuse.
        for i in range(1, len(bounds)):
            offset, sz = bounds[i - 1]

            # Calculate the bounds between the previous fragment and the
            # present one that we're iterating through.
            left = offset + sz
            right, _ = bounds[i]
            size = right - left

            # If we have a slot available, then update our result dict by
            # appending a pointer for the size we determined.
            if size > 0:
                found = position.new(left)
                result.setdefault(size, []).append(found)
            continue
        return result

    def __update_index__(self, index, update):
        '''Update the provided `update` in `index` and write them to the netnode.'''
        cls, result = self.__class__, {}
        logging.debug("{:s}.__update_index__({:#x}): Updating the index using {:d} changes.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, len(update)))

        # Iterate through all our items that need to be updated, and
        # create an `index_item` for each one.
        for idx, (position, name, content) in update.items():
            if name:
                ename, econtent = name.encode('utf-8'), content.tobytes()
                result[idx] = index_item(position, len(econtent), len(ename))
            continue

        # Now we can return the amount to adjust our index size by, and
        # the new index that we need to use.
        logging.debug("{:s}.__update_index__({:#x}): Index will change from {:d} elements to {:d}.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, len(index), len(result)))
        return len(result) - len(index), result

    def __update_table__(self, index, table, update):
        '''Update the provided `table` using the specified `update` and write them to the netnode.'''
        cls = self.__class__

        # Pre-cache a lookup table for identifying free fragments using
        # our current index. Take our keys and sort them so that we can
        # quickly find the size that we're looking for.
        free_blocks = self.__find_free_blocks__(index, update)
        free_sizes = sorted(free_blocks)

        logging.debug("{:s}.__update_table__({:#x}): Found the following free blocks for sizes ({:s}) : {!r}.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, ','.join(map("{:d}".format, free_sizes)), free_blocks))

        # Now we need to go through and check sizes to find out what actually
        # needs to be changed versus can be left-in-place.
        for index, item in update.items():

            # Read our items that we need to update
            upos, uname, ucontent = item
            name, content = uname.encode('utf-8'), ucontent.tobytes()
            utotal = len(name) + len(content)

            logging.debug("{:s}.__update_table__({:#x}): Encoded name ({!r}) for index #{:d} and contents ({!s}) with {:d} bytes.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, uname, index, ucontent, utotal))

            # Read the original items so that we can check sizes
            if index < len(table):
                opos, oindex, oname, ocontent = table[index]
                ototal = len(oname.encode('utf-8')) + len(ocontent.tobytes())

            # If it's not in our table, then it's a new item entirely
            else:
                ototal = 0

            # If our new total is smaller than the original, then
            # we're good and we don't need to re-allocate anything.
            if utotal <= ototal:
                logging.debug("{:s}.__update_table__({:#x}): Reusing block for index #{:d} ({!r}) at {!s}.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, index, uname, upos))
                continue

            logging.info("{:s}.__update_table__({:#x}): Re-allocating for index #{:d} due to change in size from {:d} to {:d}.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, index, ototal, utotal))

            # Since it wasn't smaller than the original, we need to
            # re-allocate this table. First we'll search for an
            # available slot though.
            available = next((slot for slot in free_sizes if utotal <= slot), None)

            # If we found it, then update the current item by popping
            # off a position from our free_blocks.
            if available:
                found = free_blocks[available].pop(0)
                logging.info("{:s}.__update_table__({:#x}): Found free-block ({:d}) for index #{:d} at {!s}.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, available, index, found))
                update[index] = found, uname, ucontent

                # If we emptied our free_blocks, then we need to remove the entry
                if len(free_blocks[available]) == 0:
                    free_sizes.remove(available)

                # Update our free_blocks with any leftover slackspace that we
                # aren't going to end up using.
                if available > utotal:
                    leftover, tail = available - utotal, position.new(found.int() + utotal)
                    logging.debug("{:s}.__update_table__({:#x}): Some space was left ({:d} bytes) in free-block at {!s} from index #{:d} at {!s}.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, leftover, tail, index, found))
                    free_blocks.setdefault(leftover, []).append(tail)
                    free_sizes = sorted([leftover] + free_sizes)

            # If we didn't find anything, then we need to allocate
            # space. We use None as a place-holder for that.
            else:
                logging.info("{:s}.__update_table__({:#x}): Space needs to be allocated for index #{:d} that will fit size {:d} ({:d}{:+d}).".format('.'.join([__name__, cls.__name__]), self.__cache_id__, index, utotal, len(content), len(name)))
                update[index] = None, uname, ucontent
            continue

        # Before we actually update the table, we need to pre-allocate
        # space in our netnode and fix our pointers so that they point
        # into it.
        current = start = sum(len(content.tobytes()) + len(name.encode('utf-8')) for _, _, name, content in table)
        needed = sum(len(content.tobytes()) + len(name.encode('utf-8')) for pos, name, content in update.values() if pos is None)

        for index, (pos, name, content) in update.items():
            if pos is not None:
                logging.debug("{:s}.__update_table__({:#x}): Index #{:d} ({!r}) is reusing {!s}.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, index, name, pos))
                continue

            # Calculate our new position from the current netnode size,
            # and use it to update our current item.
            newpos = position.new(current)
            update[index] = newpos, name, content

            logging.info("{:s}.__update_table__({:#x}): Index #{:d} ({!r}) will be allocated at {!s}.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, index, name, newpos))

            # Shift to the end of our current position.
            current += len(content.tobytes())
            current += len(name.encode('utf-8'))

        # Finally we can return our adjustment size, and the update
        # dictionary that we just fixed up.
        logging.debug("{:s}.__update_table__({:#x}): Total needed allocation size is {:d} bytes from {:#x} in order to grow {:d} to {:d} bytes.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, needed, start, current-needed, current))
        return needed, update

    def commit(self):
        '''Commit all changes in the index back to the netnode.'''
        cls, cache = self.__class__, {}

        # First grab our dirty cache. If any names have been removed,
        # then we'll just re-create the entire cache from it instead.
        dirty = self.__build_dirty_cache__()
        logging.debug("{:s}.update({:#x}): Satisfying commit of dirty object index: {!r}".format('.'.join([__name__, cls.__name__]), self.__cache_id__, dirty))

        if True or any(len(name) == 0 for _, name, _ in dirty.values()):
            logging.debug("{:s}.update({:#x}): Rebuild of entire object index is needed to commit changes.".format('.'.join([__name__, cls.__name__]), self.__cache_id__))
            dirty = self.__build_entire_cache__()

        logging.info("{:s}.update({:#x}): Committing with the object index: {!r}".format('.'.join([__name__, cls.__name__]), self.__cache_id__, dirty))

        # Next we need to figure out whether we need to resize the table,
        # and then how it needs to be updated.
        needed, updates = self.__update_table__(self._index, self._table, dirty)
        logging.debug("{:s}.update({:#x}): Successfully updated the table to the following: {!r}".format('.'.join([__name__, cls.__name__]), self.__cache_id__, updates))

        # Last thing to do is to figure out how the index needs to change.
        delta, newindex = self.__update_index__(self._index, updates)
        logging.debug("{:s}.update({:#x}): Successfully updated the index to the following: {!r}".format('.'.join([__name__, cls.__name__]), self.__cache_id__, newindex))

        # Now we can update our blobs with our new data starting with
        # resizing the name table.
        size = sum(len(bytearray(internal.netnode.sup.get(self.__cache_id__, index) or b'')) for index in internal.netnode.sup.fiter(self.__cache_id__))
        oldcount, oldoffset = size // SECTOR, size & (SECTOR - 1)

        logging.info("{:s}.update({:#x}): Allocating {:d} bytes from name table at offset {:#x} (sectors {:d}, bytes {:d}).".format('.'.join([__name__, cls.__name__]), self.__cache_id__, needed, size, oldcount, oldoffset))

        # Grab our last sector which is at index `oldcount` to allocate on top
        # of, and pad `needed` zeroes at its end.
        count, data = 0, bytearray(internal.netnode.sup.get(self.__cache_id__, oldcount) or b'')
        padding = b'\0' * min(needed, SECTOR - oldoffset)
        logging.debug("{:s}.update({:#x}): Padding sector #{:d} at {:d} with {:d} bytes.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, count, oldcount + count, len(padding)))
        internal.netnode.sup.set(self.__cache_id__, oldcount, memoryview(cache.setdefault(oldcount, data + padding)).tobytes())
        count, needed = count + 1, needed - len(padding)
        logging.debug("{:s}.update({:#x}): Successfully allocated {:d} bytes, only {:d} bytes left.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, len(padding), needed))

        # Now to continue padding out sectors in order to finish allocating space
        while needed > 0:
            logging.debug("{:s}.update({:#x}): Padding sector #{:d} at {:d} with {:d} bytes.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, count, oldcount + count, min(needed, SECTOR)))
            internal.netnode.sup.set(self.__cache_id__, oldcount + count, memoryview(cache.setdefault(oldcount + count, b'\0' * min(needed, SECTOR))).tobytes())
            count, needed = count + 1, needed - SECTOR

        logging.debug("{:s}.update({:#x}): Sectors {:d} to {:d} ({:d}{:+d}) were successfully allocated.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, oldcount, oldcount + count, oldcount, count))

        # Update our sups with the new data that we were given.
        for index, (pos, name, content) in updates.items():
            ename, econtent = name.encode('utf-8'), content.tobytes()

            total = sum(len(item) for item in [ename, econtent])
            logging.debug("{:s}.update({:#x}): Need to write {:d} bytes to sector {:d} at offset {:#x} for index #{:#d} ({!r}).".format('.'.join([__name__, cls.__name__]), self.__cache_id__, total, pos.sector, pos.offset, index, name))

            # Grab the sectors we need to update
            sectors = []
            for si in range(pos.sector, pos.sector + (pos.offset + total + SECTOR - 1) // SECTOR):
                data = internal.netnode.sup.get(self.__cache_id__, si)
                if data is None:
                    raise AssertionError(data)
                sectors.append(cache.setdefault(si, bytearray(data)))

            # Consolidate them so we can use slices to update them, and then
            # we can update our content, and then its name.
            offset, data = pos.offset, functools.reduce(operator.add, sectors, bytearray())

            offset += 0
            data[offset : offset + len(econtent)] = econtent

            offset += len(econtent)
            data[offset : offset + len(ename)] = ename

            # Now we need to break the data back into sectors, and write them back
            logging.info("{:s}.update({:#x}): Writing {:d} sectors for index #{:#d} ({!r}) to sector {:d}.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, len(sectors), index, name, pos.sector))
            for i, item in enumerate(sectors):
                sector = cache[pos.sector + i] = data[i * SECTOR : i * SECTOR + SECTOR]
                internal.netnode.sup.set(self.__cache_id__, pos.sector + i, memoryview(sector).tobytes())

            self._dirty.pop(index, None)

        # Now we can update the index and then we're done.

        # FIXME: This shouldn't be done with a blob, and should be using supvals. The
        #        The build_entire_cache() conditional at the top of this function has
        #        been modified to always regenerate the index, so that will need to be
        #        fixed in order to enable partial updates...

        logging.info("{:s}.update({:#x}): Writing {:d} items for new index.".format('.'.join([__name__, cls.__name__]), self.__cache_id__, len(newindex)))

        data = []
        for idx in sorted(newindex):

            # If this name has been removed, then don't include this object
            # in our new index.
            if operator.contains(updates, idx):
                _, name, _ = updates[idx]
                if len(name) == 0:
                    continue
                pass

            item = newindex[idx]
            data.append(item.tobytes())

        internal.netnode.blob.set(self.__cache_id__, Index.itag, bytes().join(data))

        # XXX: Originally I didn't know that blobs would trash the rest of the blob in
        #      the netnode when setting them...were blobs always like that? Does IDA
        #      really expect you to read the whole damned blob into memory?

        # Final thing to do is to update our name table whilst ensuring we don't add
        # items that have been removed. Update the cache at the same time.
        self._cache, result = {}, []
        for index, (pos, name, content) in updates.items():
            if len(name) > 0:
                self._cache[name] = len(result)
                result.append((pos, index, name, content))
            continue
        self._table[:] = result

        # ...and then reset our index
        self._index[:] = [newindex[index] for index in sorted(newindex)]
        return True

class content_item(namedtypedtuple):
    _fields = 'position', 'meta', 'content'
    _types = position, six.integer_types

    @classmethod
    def size(self):
        return position.size() + 2 * INTEGER_SIZE

    @classmethod
    def ofbytes(cls, data):
        typecode = internal.utils.get_array_typecode(INTEGER_SIZE)
        res = array.array(typecode)
        res.fromstring(data)
        return cls(position(*res[:2].tolist()), *res[2:].tolist())

    def tobytes(self):
        position, name, content = self
        typecode = internal.utils.get_array_typecode(INTEGER_SIZE)
        res = array.array(typecode, [name, content])
        return position.tobytes() + memoryview(buffer(res)).tobytes()

class FS(object):
    contents = '$ filesystem.contents'
