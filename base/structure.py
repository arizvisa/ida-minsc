import sys,database,logging,re,fnmatch,itertools,inspect
'''
structure-context

generic tools for working in the context of a structure.
'''

## FIXME: need to add support for a union_t. add_struc takes another parameter
##        that defines whether a structure is a union or not.

import idaapi
def name(id, name=None):
    """set/get the name of a particular structure"""
    if name is None:
        return idaapi.get_struc_name(id)
    return idaapi.set_struc_name(id, name)

def comment(id, cmt=None, repeatable=1):
    """set/get the comment of a particular structure"""
    if cmt is None:
        return idaapi.get_struc_cmt(id, repeatable)
    return idaapi.set_struc_cmt(id, cmt, repeatable)

def index(id, index=None):
    """set/get the index of a particular structure"""
    if index is None:
        return idaapi.get_struc_idx(id)
    return idaapi.set_struc_idx(id, index)

def list(*args, **type):
    """List all the structures within the database.

    Search type can be identified by providing a named argument.
    like = glob match
    regex = regular expression
    index = particular index
    identifier = particular id number
    pred = function predicate
    """

    # FIXME: refactor this implementation into a utility module
    #        so that this can be reused elsewhere
    if len(args) == 1: type['like'] = args[0]
    if 'regex' in type:
        match = lambda x: re.search(type['regex'], x.name)
    elif 'index' in type:
        match = lambda x: idaapi.get_struc_idx(x.id) == type['index']
    elif 'identifer' in type:
        match = lambda x: x.id == type['identifier']
    elif 'like' in type:
        match = lambda x: fnmatch.fnmatch(x.name, type['like'])
    elif 'pred' in type:
        match = type['pred']
    else:
        match = bool

    for st in itertools.ifilter(match,iterate()):
        print '[%d] %s +%x (%d members)%s'%(idaapi.get_struc_idx(st.id), st.name, st.size, len(st.members), st.comment and ' // %s'%st.comment or '')
    return

def search(*args, **type):
    """Search through all the structures within the database and return the first result.
    
    Search type can be identified by providing a named argument.
    like = glob match
    regex = regular expression
    index = particular index
    identifier = particular id number
    """
    try:
        if len(args) == 1: type['like'] = args[0]

        if type:
            if 'regex' in type:
                match = lambda x: re.search(type['regex'], x.name)
            elif 'index' in type:
                match = lambda x: idaapi.get_struc_idx(x.id) == type['index']
            elif 'identifer' in type:
                match = lambda x: x.id == type['identifier']
            elif 'like' in type:
                match = lambda x: fnmatch.fnmatch(x.name, type['like'])
            elif 'pred' in type:
                match = type['pred']
            else:
                raise LookupError
    except:
        raise LookupError, 'Unable to determine search type : %r'% (args or type)

    res = filter(match,iterate())
    if len(res) > 1:
        logging.warn('structure.search(%s) : Found %d results, returning the first one.'% (args and 'match' or type.iterkeys().next(), len(res)))
        fn = lambda x: sys.stdout.write(x + "\n")
        map(logging.info, (('[%d] %s'%(idaapi.get_struc_idx(x.id),x.name)) for i,x in enumerate(res)))
    return itertools.ifilter(match,iterate()).next()

def iterate():
    """Iterate through all structures defined in the database"""
    idx = idaapi.get_first_struc_idx()
    while idx != idaapi.get_last_struc_idx():
        identifier = idaapi.get_struc_by_idx(idx)
        yield instance(identifier)
        idx = idaapi.get_next_struc_idx(idx)
    idx = idaapi.get_last_struc_idx()
    yield instance(idaapi.get_struc_by_idx(idx))

def size(id):
    """Return the size of the specified structure"""
    return idaapi.get_struc_size(id)

def members(id):
    """Return the ((offset,size),(name,comment)) of each member within the specified structure"""
    st = idaapi.get_struc(id)
    if not st:
        # empty structure
        return

    size = idaapi.get_struc_size(st)

    offset = 0
    for i in range(st.memqty):
        m = st.get_member(i)
        ms = idaapi.get_member_size(m)

        left,right = m.soff,m.eoff

        if offset < left:
            yield (offset,left-offset), (None,None)
            offset = left

        yield (offset,ms),(idaapi.get_member_name(m.id), idaapi.get_member_cmt(m.id, 1))
        offset += ms
    return

def fragment(id, offset, size):
    """Return the ((offset,size),(name,comment)) of all members of a structure beginning at ``offset`` until ``size``"""
    member = members(id)

    # seek
    while True:
        (m_offset,m_size),(m_name,m_cmt) = member.next()

        left,right = m_offset, m_offset+m_size
        if (offset >= left) and (offset < right):
            yield (m_offset,m_size),(m_name,m_cmt)
            size -= m_size
            break
        continue

    # return
    while size > 0:
        (m_offset,m_size),(m_name,m_cmt) = member.next()
        yield (m_offset,m_size),(m_name,m_cmt)
        size -= m_size

    return

def get(name):
    id = idaapi.get_struc_id(name)
    if id == idaapi.BADADDR:
        try: raise DeprecationWarning
        except: logging.warn('%s.get auto-creation is being deprecated'% __name__, exc_info=True)
        id = idaapi.add_struc(idaapi.BADADDR, name)
    return instance(id)

def new(name, offset=0):
    """Create a new structure ``name`` and return an instance of it"""
    id = idaapi.add_struc(idaapi.BADADDR, name)
    assert id != idaapi.BADADDR
    # FIXME: we should probably move the new structure to the end of the list via set_struc_idx
    return instance(id, offset=offset)

def by(value, **options):
    """Return a structure by it's name or index"""
    if isinstance(value, str):
        return byName(value, **options)
    elif isinstance(value, (int,long)) and value > 0:
        return byIndex(value, **options)
    return LookupError, (type(value), value)

def byName(name, **options):
    """Return a structure by it's name"""
    id = idaapi.get_struc_id(name)
    if id == idaapi.BADADDR:
        raise LookupError, 'Unable to locate structure {!r}'.format(name)
    return instance(id, **options)

def byIndex(index, **options):
    """Return a structure by it's index"""
    id = idaapi.get_struc_by_idx(index)
    if id == idaapi.BADADDR:
        raise IndexError, 'Unable to locate structure #{:d}'.format(index)
    return instance(id, **options)

def instance(identifier, **options):
    """Returns the structure_t identified by ``identifier``"""
    try:
        cache = instance.cache
    except AttributeError:
        instance.cache = {}
        return instance(identifier, **options)
    res = cache.setdefault((identifier,options.get('offset',0)), structure_t(identifier, **options))
    if 'offset' in options:
        res.offset = options['offset']
    return res

### structure_t abstraction
class structure_t(object):
    """An abstraction around an IDA structure"""
    __slots__ = ('__id', '__members')
    
    def __init__(self, id, offset=0):
        self.__id = id
        self.__members = members_t(self, baseoffset=offset)

    @property
    def id(self):
        return self.__id
    @property
    def ptr(self):
        return idaapi.get_struc(self.id)
    @property
    def members(self):
        return self.__members

    def __getstate__(self):
        cmtt = idaapi.get_struc_cmt(self.id, True)
        cmtf = idaapi.get_struc_cmt(self.id, False)
        # FIXME: perhaps we should preserve the get_struc_idx result too
        return (self.name,(cmtt,cmtf),self.members)
    def __setstate__(self, state):
        name,(cmtt,cmtf),members = state
        identifier = idaapi.get_struc_id(name)
        if identifier == idaapi.BADADDR:
            logging.warn('Creating structure %s [%d fields]%s'% (name, len(members), ' // %s'%(cmtf or cmtt) if cmtf or cmtt else ''))
            identifier = idaapi.add_struc(idaapi.BADADDR, name)
        # FIXME: although set_struc_idx and stuff doesn't seem too important.
        idaapi.set_struc_cmt(identifier, cmtt, True)
        idaapi.set_struc_cmt(identifier, cmtf, False)
        self.__id = identifier
        self.__members = members
        return

    @property
    def name(self):
        return idaapi.get_struc_name(self.id)
    @name.setter
    def name(self, name):
        return idaapi.set_struc_name(self.id, name)
    @property
    def comment(self):
        return idaapi.get_struc_cmt(self.id, True)
    @comment.setter
    def comment(self, comment):
        return idaapi.set_struc_cmt(self.id, comment, True)
    @property
    def size(self):
        return idaapi.get_struc_size(self.ptr)
    @property
    def offset(self):
        return self.members.baseoffset
    @offset.setter
    def offset(self, value):
        res,self.members.baseoffset = self.members.baseoffset,value
        return res
    @property
    def index(self):
        return idaapi.get_struc_idx(self.id)
    @index.setter
    def index(self, value):
        return idaapi.set_struc_idx(self.ptr, value)

    def destroy(self):
        return idaapi.del_struc(self.ptr)

    def __repr__(self):
        return "<type 'structure' name=%r%s size=+%x>%s"% (self.name, (' offset=%x'%self.offset if self.offset > 0 else ''), self.size, ' // %s'%self.comment if self.comment else '')

    def field(self, ofs):
        return self.members.byOffset(ofs + self.members.baseoffset)
    
    def copy(self, name):
        '''Copy members into the structure ``name``'''
        raise NotImplementedError

    def resize(self, size):
        raise NotImplementedError
        # FIXME: re-assign this method as a setter for .size
        res = idaapi.expand_struc(self.ptr, 0, size, recalc=True)
        if not res:
            logging.fatal('structure_t.resize : Issue resizing %s : %x'%(self.name, size))
        return res

    def __getattr__(self, name):
        return getattr(self.members, name)

    #def resize(self, size):

class members_t(object):
    """An abstraction around the members of a particular IDA structure

    This allows one to treat each member as a dict.
    """
    __slots__ = ('__owner', 'baseoffset')

    # members state
    @property
    def owner(self):
        return self.__owner
    @property
    def ptr(self):
        return self.__owner.ptr.members
    def __init__(self, owner, baseoffset=0):
        self.__owner = owner
        self.baseoffset = baseoffset

    def __getstate__(self):
        return (self.owner.name,self.baseoffset,map(self.__getitem__,range(len(self))))
    def __setstate__(self, state):
        ownername,baseoffset,_ = state
        identifier = idaapi.get_struc_id(ownername)
        if identifier == idaapi.BADADDR:
            raise LookupError, 'Failure creating a members_t for structure_t {!r}'.format(ownername)
            logging.warn('members_t : Creating structure %s -- [%x] %d members'% (ownername, baseoffset, len(members)))
            identifier = idaapi.add_struc(idaapi.BADADDR, ownername)
        self.baseoffset = baseoffset
        self.__owner = instance(identifier, offset=baseoffset)
        return 

    # fetching members
    def __len__(self):
        return 0 if self.owner.ptr is None else self.owner.ptr.memqty
    def __iter__(self):
        for idx in xrange(len(self)):
            yield member_t(self.owner, idx)
        return
    def __getitem__(self, index):
        if isinstance(index, (int,long)):
            index = self.owner.ptr.memqty + index if index < 0 else index
            res = member_t(self.owner, index) if index >= 0 and index < self.owner.ptr.memqty else None
        elif isinstance(index, str):
            res = self.byname(index)
        elif isinstance(index, slice):
            res = [self.__getitem__(i) for i in range(self.owner.ptr.memqty)].__getitem__(index)
        else:
            raise TypeError, index

        if res is None:
            raise IndexError, index
        return res

    def index(self, member_t):
        for i in range(0, self.owner.ptr.memqty):
            if member_t.id == self[i].id:
                return i
            continue
        raise ValueError, '%r not in list'% member_t

    # searching members
    def list(self, *args, **type):

        # FIXME: refactor this implementation into a utility module
        #        so that this can be reused elsewhere
        if len(args) == 1:
            type['like'] = args[0]
        if 'regex' in type:
            match = lambda x: re.search(type['regex'], x.name)
        elif 'index' in type:
            match = lambda x: idaapi.get_struc_idx(x.id) == type['index']
        elif 'identifer' in type:
            match = lambda x: x.id == type['identifier']
        elif 'like' in type:
            match = lambda x: fnmatch.fnmatch(x.name, type['like'])
        elif 'pred' in type:
            match = type['pred']
        else:
            match = bool
        for x in itertools.ifilter(match,self):
            print '[%d] %s %x:+%x %r(%x,%x%s)%s'%(x.index, x.name, x.offset, x.size, x.type, x.flag, x.dt_type, '' if x.typeid is None else ', %x'%x.typeid, x.comment and ' // %s'%x.comment or '')
        return

    def byName(self, name):
        mem = idaapi.get_member_by_name(self.owner.ptr, str(name))
        if mem is None: raise KeyError, name
        index = self.index(mem)
        return self[index]
    byname=byName
    def byFullname(self, fullname):
        mem = idaapi.get_member_by_fullname(self.owner.ptr, str(fullname))
        if mem is None: raise KeyError, fullname
        index = self.index(mem)
        return self[index]
    byfullname = byFullname
    def byOffset(self, offset):
        min,max = map(lambda sz: sz - self.baseoffset, (idaapi.get_struc_first_offset(self.owner.ptr),idaapi.get_struc_last_offset(self.owner.ptr)))
        if (offset < min) or (offset >= max):
            logging.warn('structure_t(%s).members.byoffset : Requested offset %x not within bounds (%x,%x). Trying anyways..'%(self.owner.name, offset, min, max))

        mem = idaapi.get_member(self.owner.ptr, offset - self.baseoffset)
        if mem is None:
            logging.warn('structure_t(%s).members.byoffset : Unable to locate member at offset %x. Trying get_best_fit_member instead.'%(self.owner.name, offset - self.baseoffset))
            mem = idaapi.get_best_fit_member(self.owner.ptr, offset - self.baseoffset)
        if mem is None:
            raise IndexError, offset
        index = self.index(mem)
        return self[index]
    byoffset = byOffset

    # adding/removing members
    def add(self, name, offset, type):
        """Add a member at ``offset`` with the given ``name`` and ``type``.

        To specify a particular size, ``type`` can be a tuple with the second element referring to the size.
        """
        flag,typeid,nbytes = typemap.resolve(type)

        # FIXME: handle .strtype (strings), .ec (enums), .cd (custom)
        opinfo = idaapi.opinfo_t()
        opinfo.tid = typeid
        realoffset = offset - self.baseoffset
        if name is None:
            logging.warn('members_t.add : name is undefined, defaulting to offset %x'%(realoffset))
            name = 'v_%x'%realoffset

        res = idaapi.add_struc_member(self.owner.ptr, name, realoffset, flag, opinfo, nbytes)
        if res == idaapi.STRUC_ERROR_MEMBER_OK:
            logging.info('members_t.add : idaapi.add_struc_member(sptr=%s, fieldname=%s, offset=%x, flag=%x, mt=%x, nbytes=%x) : Success'%(self.owner.name, name, realoffset, flag, typeid, nbytes))
        else:
            error = {
                idaapi.STRUC_ERROR_MEMBER_NAME : 'Duplicate field name',
                idaapi.STRUC_ERROR_MEMBER_OFFSET : 'Invalid offset',
                idaapi.STRUC_ERROR_MEMBER_SIZE : 'Invalid size',
            }
            callee = 'idaapi.add_struc_member(sptr=%s, fieldname=%s, offset=%x, flag=%x, mt=%x, nbytes=%x)'% (self.owner.name, name, realoffset, flag, typeid, nbytes)
            logging.fatal(' : '.join(('members_t.add', callee, error.get(res, 'Error code %x'%res))))
            return None

        res = idaapi.get_member(self.owner.ptr, realoffset)
        if res is None:
            logging.fatal("member_t.create : Failed creating member %s %x:+%x", name, realoffset, nbytes)

        # sloppily figure out what the correct index is
        idx = self.index( idaapi.get_member(self.owner.ptr, realoffset) )
        return member_t(self.owner, idx)

    def pop(self, index):
        item = self[index]
        return self.remove(item.offset - self.baseoffset)
    def __delitem__(self, index):
        return self.pop(index)

    def remove(self, *args):
        """remove(offset) or remove(offset,size)"""
        try:
            offset,size = args
        except:
            offset, = args
            return idaapi.del_struc_member(self.owner.ptr, offset - self.baseoffset)
        ofs = offset - self.baseoffset
        return idaapi.del_struc_members(self.owner.ptr, ofs, ofs+size)

    # displaying members
    def __repr__(self):
        result = []
        for i in xrange(len(self)):
            m = self[i]
            name,t,ofs,size,comment = m.name,m.type,m.offset,m.size,m.comment
            result.append((i, name,t,ofs,size,comment))
        return '%s\n%s'%(type(self), '\n'.join(' [%d] %s %s {%x:+%x}%s'%(i,n,repr(t),o,s,' // %s'%c if c is not None else '') for i,n,t,o,s,c in result))

class member_t(object):
    '''Contains information about a particular member within a given structure'''
    __slots__ = ('__owner', '__index')

    ## constructors
    def __init__(self, owner, index):
        self.__index = index
        self.__owner = owner

    def __getstate__(self):
        t = (self.flag,None if self.typeid is None else instance(self.typeid),self.size)
        cmtt = idaapi.get_member_cmt(self.id, True)
        cmtf = idaapi.get_member_cmt(self.id, False)
        ofs = self.offset - self.__owner.members.baseoffset
        return (self.__owner.name,self.__index,self.name,(cmtt,cmtf),ofs,t)
    def __setstate__(self, state):
        ownername,index,name,(cmtt,cmtf),ofs,t = state

        identifier = idaapi.get_struc_id(ownername)
        if identifier == idaapi.BADADDR:
            logging.warn('member_t : Creating structure %s -- [%x] %s%s'% (ownername, ofs, name, ' // %s'%(cmtt or cmtf) if cmtt or cmtf else ''))
            identifier = idaapi.add_struc(idaapi.BADADDR, ownername)
        self.__owner = owner = instance(identifier, offset=0)

        flag,mytype,nbytes = t

        # FIXME: handle .strtype (strings), .ec (enums), .cd (custom)
        opinfo = idaapi.opinfo_t()
        opinfo.tid = 0 if mytype is None else mytype.id 

        res = idaapi.add_struc_member(owner.ptr, name, ofs, flag, opinfo, nbytes)

        # FIXME: handle these errors properly
        # duplicate name
        if res == idaapi.STRUC_ERROR_MEMBER_NAME:
            if idaapi.get_member_by_name(owner.ptr, name).soff != ofs:
                newname = '%s_%x'%(name,ofs)
                logging.warn('structure_t(%s).member_t : Duplicate name found for %s, renaming to %s'%(ownername, name, newname))
                idaapi.set_member_name(owner.ptr, ofs, newname)
            else:
                logging.info('structure_t(%s).member_t : Field at %x contains the same name %s'%(ownername, ofs, name))
        # duplicate field
        elif res == idaapi.STRUC_ERROR_MEMBER_OFFSET:
            logging.info('structure_t(%s).member_t : Field already found at %x. Overwriting with %s'%(ownername, ofs, name))
            idaapi.set_member_type(owner.ptr, ofs, flag, opinfo, nbytes)
            idaapi.set_member_name(owner.ptr, ofs, name)
        # invalid size
        elif res == idaapi.STRUC_ERROR_MEMBER_SIZE:
            logging.warn('member_t : Issue creating structure member %s.%s : %x'%(ownername, name, res))
        # unknown
        elif res != idaapi.STRUC_ERROR_MEMBER_OK:
            logging.warn('member_t : Issue creating structure member %s.%s : %x'%(ownername, name, res))

        self.__index = index
        self.__owner = owner

        idaapi.set_member_cmt(self.ptr, cmtt, True)
        idaapi.set_member_cmt(self.ptr, cmtf, False)
        return

    # read-only properties
    @property
    def ptr(self):
        return self.__owner.ptr.get_member(self.__index)
    @property
    def id(self):
        return self.ptr.id
    @property
    def size(self):
        return idaapi.get_member_size(self.ptr)
    @property
    def offset(self):
        return self.ptr.get_soff() + self.__owner.members.baseoffset
    @property
    def flag(self):
        m = idaapi.get_member(self.__owner.ptr, self.offset - self.__owner.members.baseoffset)
        return 0 if m is None else m.flag
    @property
    def fullname(self):
        return idaapi.get_member_fullname(self.id)
    @property
    def typeid(self):
        opinfo = idaapi.opinfo_t()
        res = idaapi.retrieve_member_info(self.ptr, opinfo)
        return None if res is None else res.tid if res.tid != idaapi.BADADDR else None
    @property
    def index(self):
        return self.__index
    @property
    def left(self):
        return self.ptr.soff
    @property
    def right(self):
        return self.ptr.eoff

    # read/write properties
    @property
    def name(self):
        return idaapi.get_member_name(self.id) or ''
    @name.setter
    def name(self, value):
        return idaapi.set_member_name(self.__owner.ptr, self.offset - self.__owner.members.baseoffset, value)
    @property
    def comment(self):
        return idaapi.get_member_cmt(self.id, True)
    @comment.setter
    def comment(self, value):
        return idaapi.set_member_cmt(self.ptr, value, True)
    @property
    def dt_type(self):
        m = idaapi.get_member(self.__owner.ptr, self.offset - self.__owner.members.baseoffset)
        if m is None:
            return 0
        flag = m.flag & self.FF_MASK

        # idaapi(swig) and python have different definitions of what constant values are
        max = (sys.maxint+1)*2
        return flag if flag < sys.maxint else flag - max
    @property
    def type(self):
        res = typemap.dissolve(self.flag,self.typeid,self.size)
        if isinstance(res, structure_t):
            res = instance(res.id, offset=self.offset)
        elif isinstance(res, tuple):
            t,sz = res
            if isinstance(t, structure_t):
                t = instance(t.id, offset=self.offset)
            elif isinstance(t, [].__class__) and isinstance(t[0], structure_t):
                t[0] = instance(t[0].id, offset=self.offset)
            res = t,sz   
        return res
    @type.setter
    def type(self, type):
        flag,typeid,size = typemap.resolve(type)
        opinfo = idaapi.opinfo_t()
        opinfo.tid = typeid
        return idaapi.set_member_type(self.__owner.ptr, self.offset, flag, opinfo, size)

    #def resize(self, size):
    #    # FIXME: re-assign this method as a setter for .size
    #    res = idaapi.expand_struc(self.owner.ptr, self.offset, size, recalc=True)
    #    if not res:
    #        logging.fatal('structure_t(%r).member_t[%d].resize : Issue resizing field %s : %x'%(self.owner.name, self.index, self.fullname, size))
    #    return res

    # friendly description of a particular member
    def __repr__(self):
        id,name,typ,comment = self.id,self.name,self.type,self.comment
        return '%s [%d] %s %s {%x:+%x}%s'%( type(self), self.index, name, repr(typ), self.offset, self.size, ' // %s'%comment if comment is not None else '')

# FIXME: move this typemap code under a shared utility module of some kind
class typemap:
    """Convert bidirectionally from a pythonic type into an IDA type"""

    FF_MASK = 0xfff00000    # Mask that specifies the structure's type
    # FIXME: In some cases FF_nOFF (where n is 0 or 1) does not actually
    #        get auto-treated as an pointer by ida. Instead, it appears to
    #        only get marked as an "offset" and rendered as an integer.

    integermap = {
        1:(idaapi.byteflag(), -1),  2:(idaapi.wordflag(), -1),  3:(idaapi.tribyteflag(), -1),
        4:(idaapi.dwrdflag(), -1),  8:(idaapi.qwrdflag(), -1), 10:(idaapi.tbytflag(), -1),
        16:(idaapi.owrdflag(), -1),
    }
    if hasattr(idaapi, 'ywrdflag'): integermap[32] = getattr(idaapi, 'ywrdflag')(),-1

    decimalmap = {
         4:(idaapi.floatflag(), -1),     8:(idaapi.doubleflag(), -1),
        10:(idaapi.packrealflag(), -1), 12:(idaapi.packrealflag(), -1),
    }

    stringmap = {
        str:(idaapi.asciflag(), idaapi.ASCSTR_TERMCHR),
        unicode:(idaapi.asciflag(),idaapi.ASCSTR_UNICODE),
    }
    
    charmap = { chr:(idaapi.charflag(),-1), }
    ptrmap = { sz : (idaapi.offflag()|flg, tid) for sz,(flg,tid) in integermap.iteritems() }

    typemap = {
        int:integermap,long:integermap,float:decimalmap,
        str:stringmap,unicode:stringmap,chr:charmap,
        type:ptrmap,
    }

    # inverted lookup table
    inverted = {}
    for s,(f,_) in integermap.items():
        inverted[f & FF_MASK] = (int,s)
    for s,(f,_) in decimalmap.items():
        inverted[f & FF_MASK] = (float,s)
    for s,(f,_) in stringmap.items():
        inverted[f & FF_MASK] = (str,s)
    for s,(f,_) in ptrmap.items():
        inverted[f & FF_MASK] = (type,s)
    del f
    inverted[idaapi.FF_STRU] = (int,1)  # FIXME: hack for dealing with
                                        #   structures that have the flag set
                                        #   but aren't actually structures..

    # defaults
    integermap[None] = integermap[(hasattr(database,'config') and database.config.bits() or 32)/8]
    decimalmap[None] = decimalmap[(hasattr(database,'config') and database.config.bits() or 32)/8]
    ptrmap[None] = ptrmap[(hasattr(database,'config') and database.config.bits() or 32)/8]
    stringmap[None] = stringmap[str]
    charmap[None] = charmap[chr]

    @classmethod
    def dissolve(cls, flag, typeid, size):
        dt = flag & cls.FF_MASK
        sf = -1 if idaapi.is_signed_data(flag) else +1
        if dt == idaapi.FF_STRU and isinstance(typeid,(int,long)):
            t = instance(typeid) 
            sz = t.size
            return t if sz == size else ([t],size // sz)
        if dt not in cls.inverted:
            logging.warn('typemap.disolve(%r, %r, %r) : Unable to identify a pythonic type'% (dt, typeid, size))
        t,sz = cls.inverted[dt]
        res = t if sz == size else [t,sz * sf]
        return res if sz == size else (res,size)

    @classmethod
    def resolve(cls, type):
        """Return ida's (flag,typeid,size) given the type (type,size) or (type/instance)
        (int,4)     -- a dword
        ([int,4],8) -- an array of 8 dwords
        (str,10)    -- an ascii string of 10 characters
        (int,2)     -- a word
        (chr,4)     -- an array of 4 characters
        """

        # FIXME: Array definitions seem awkward, I think they should look
        #        like [type, length] and so an array of 4 words should be
        #        [(int,2), 4]

        # return idaapi.FF_xxx, typeid, and size given a tuple (type,size) or just a type/instance
        type,nbytes = type if isinstance(type, tuple) else (type,None)

        # FIXME: this explicit checking of nbytes being None is sloppy
        size = 0 if nbytes is None else abs(nbytes)

        # structure -- structure_t
        if isinstance(type, structure_t):
            flag,typeid = idaapi.struflag(),type.id

        elif type is None:
            flag,typeid = idaapi.alignflag(),-1

        elif isinstance(type,[].__class__):
            flag,typeid,nb = cls.resolve(tuple(type)) if len(type)>1 else cls.resolve(*type)
            size = nb if nbytes is None else (size*nb)    # FIXME

        # defined in typemap -- (type,size)
        else:
            table = cls.typemap[type]
            if type in (int,long,float,type):
                flag,typeid = table[None if nbytes is None else size]   # FIXME
            else:
                flag,typeid = table[type]

        # automatically determine the size for the requested typeid
        if nbytes is None:
            opinfo = idaapi.opinfo_t()
            opinfo.tid = typeid
            size = idaapi.get_data_type_size(flag, opinfo)

        elif nbytes < 0:
            flag |= idaapi.signed_data_flag()

        return flag,typeid,size
