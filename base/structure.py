import idc, comment, database
'''
structure-context

generic tools for working in the context of a structure.
'''

import idaapi
def get(id):
    return idaapi.get_struc(id)

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
