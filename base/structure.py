import sys, idc, comment, database
'''
structure-context

generic tools for working in the context of a structure.
'''

import idaapi
def name(id, name=None):
    if name is None:
        return idc.GetStrucName(id)
    return idc.SetStrucName(id, name)

def search(name):
    return idc.GetStrucIdByName(name)

def size(id):
    return idc.GetStrucSize(id)

def members(id):
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
        id = idaapi.add_struc(name)
    return instance(id)

class instance(object):
    def __init__(self, id):
        self.__id = id
        self.__members = self.members_t(self)

    __id = 0
    @property
    def id(self):
        return self.__id
    @property
    def ptr(self):
        return idaapi.get_struc(self.id)
    @property
    def members(self):
        return self.__members

    def __getitem__(self, index):
        return self.members[index]

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

    def destroy(self):
        return idaapi.del_struc(self.ptr)

    def __repr__(self):
        return "<type 'structure'> %s [%d] %s %s"% (self.name, len(self.members), ','.join(x.name for x in self.members), self.comment or '')

    class members_t(object):
        @property
        def owner(self):
            return self.__owner
        def __init__(self, owner):
            self.__owner = owner
            self.__cache = self.__updatecache()
        def __updatecache(self):
            result = {}
            for i in xrange(len(self)):
                result[i] = self.owner.member_t.fetch(self, i)
            return result

        def __iter__(self):
            for i in xrange(len(self)):
                yield self[i]
        def __getitem__(self, index):
            try:
                return self.__cache[index]
            except KeyError:
                self.__cache[index] = self.owner.member_t.fetch(self, index)
            return self[index]
        def __len__(self):
            return self.owner.ptr.memqty

        def byname(self, name):
            index = idaapi.get_member_by_name(self.owner.ptr, name)
            return self[index]
        def byfullname(self, fullname):
            index = idaapi.get_member_by_fullname(self.owner.ptr, fullname)
            return self[index]

        def add(self, name, type, offset, size):
            m = self.member_t.create(self, name, offset, type, size)
            self.__cache[m.id] = m
            return m
        def __delitem__(self, index):
            item = self.pop(index)
            return idaapi.del_struc_member(self.ptr, item.offset)

        def __repr__(self):
            result = []
            for i in xrange(len(self)):
                m = self[i]
                name,t,ofs,size,comment = m.name,m.type,m.offset,m.size,m.comment
                result.append((i, name,t,ofs,size,comment))
            return '%s\n%s'%(type(self), '\n'.join(' [%d] %s %s {%x:+%x} %s'%(i,n,repr(t),o,s,'// %s'%c if c is not None else '') for i,n,t,o,s,c in result))

    class member_t(object):
        integer = {
            1:(idaapi.FF_BYTE,-1), 2:(idaapi.FF_WORD,-1), 3:(idaapi.FF_3BYTE,-1), 4:(idaapi.FF_DWRD,-1),
            8:(idaapi.FF_QWRD,-1), 10:(idaapi.FF_TBYT,-1), 16:(idaapi.FF_OWRD,-1), 32:(idaapi.FF_YWRD,-1),
        }
        decimal = {
            4:(idaapi.FF_FLOAT,-1), 8:(idaapi.FF_DOUBLE,-1), 10:(idaapi.FF_PACKREAL,-1), 12:(idaapi.FF_PACKREAL,-1),
        }
        string = {
            str:(idaapi.FF_ASCI,idaapi.ASCSTR_TERMCHR), unicode:(idaapi.FF_ASCI,idaapi.ASCSTR_UNICODE),
        }
        type = {
            int:integer,long:integer,float:decimal,str:string,unicode:string
            #FF_ALIGN, FF_CUSTOM, FF_STRU
        }
        inverted = {}
        for _,(f,_) in integer.items():
            inverted[f] = int
        for _,(f,_) in decimal.items():
            inverted[f] = float
        for _,(f,_) in string.items():
            inverted[f] = str
        del f

        ## constructors
        @classmethod
        def fetch(cls, owner, index):
            result = type(cls.__name__, (cls,), {'index':index})
            return result(owner)
        @classmethod
        def create(cls, owner, name, offset, type, nbytes):
            flag,typeid = self.__determine_type(type, nbytes)
            index = idaapi.add_struc_member(owner, name, offset, flag, typeid, nbytes)
            return cls.fetch(owner, index)
        def __init__(self, members):
            self.index
            self.__owner = members.owner

        def __determine_type(self, type, nbytes):
            if type in cls.type:
                table = cls.type[type]
                if type in (str,unicode):
                    flag,typeid = table[type]
                else:
                    flag,typeid = table[nbytes]
            else:
                assert isinstance(type,instance), 'must be a valid structure'
                flag,typeid = idaapi.FF_STRU,type.id
            return flag,typeid

        @property
        def ptr(self):
            return self.__owner.ptr.get_member(self.index)
        @property
        def id(self):
            return self.ptr.id
        @property
        def size(self):
            return idaapi.get_member_size(self.ptr)
        @property
        def offset(self):
            return self.ptr.get_soff()

        @property
        def name(self):
            return idaapi.get_member_name(self.id)
        @name.setter
        def name(self, value):
            return idaapi.set_member_name(self.owner.ptr, self.offset, value)
        @property
        def fullname(self):
            return idaapi.get_member_fullname(self.id)
        @property
        def comment(self):
            return idaapi.get_member_cmt(self.id, True)
        @comment.setter
        def comment(self, value):
            return idaapi.set_member_cmt(self.ptr, value, True)
        @property
        def dt_type(self):
            m = idaapi.get_member(self.__owner.ptr, self.offset)
            if m is None:
                return 0
            flag = m.flag & idaapi.DT_TYPE

            # idaapi(swig) and python have different definitions of what constant values are
            max = (sys.maxint+1)*2
            return flag if flag < sys.maxint else flag - max
        @property
        def type(self):
            flag = self.dt_type
            if flag == idaapi.FF_STRU:
                id = idaapi.get_sptr(self.ptr).id
                return instance(id)
            return self.inverted[flag]
        @type.setter
        def type(self, (type,size)):
            flag,typeid = self.__determine_type(type,size)
            return idaapi.set_member_type(self.owner.ptr, self.offset, flag, typeid, size)

        def __repr__(self):
            id,name,typ,comment = self.id,self.name,self.type,self.comment
            return '%s [%d] %s %s {%x:+%x} %s'%( type(self), self.index, name, repr(typ),self.offset, self.size, '// %s'%comment if comment is not None else '')
