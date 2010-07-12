from ptypes import *

class Node(pstruct.type):
    def follow(self, name):
        p = self
        while int(p[name]) != 0:
            p = p[name].get().load()
            yield p
        return

    def id(self):
        return 'Node_%08x'%(self.getoffset())

    def parentNode(self):
        return self.follow('parentNode')

    def getroot(self):
        for x in self.parentNode():
            pass
        return x

    def children(self):
        start,end = self['firstChild'].get(), self['lastChild'].get()

        while (start.getoffset() != 0) and (start.getoffset() != end.getoffset()) and start.getoffset() != self.getoffset():
            yield start.load()
            start = start['nextSibling'].get()
        if end.getoffset() != 0:
            yield end.load()
        return

    def render_dot(self, out):
        parent = self['parentNode']
        if int(parent) != 0:
            parent = parent.get().load()
            out.write('%s -- %s;\n'%( self.id(), parent.id()))

        for child in self.children():
            out.write('%s -- %s;\n'%( child.id(), self.id() ))
            try:
                child.render_dot(out)
            except Exception,e:
                continue
        return

Node._fields_ = [
        (dyn.addr_t, '`vftable`'),
        (dyn.block(0x8), 'unknown_1'),
        (dyn.pointer(Node), 'parentNode'),      # c
        (dyn.pointer(Node), 'previousSibling'), # 10
        (dyn.pointer(Node), 'nextSibling'),     # 14
        (dyn.block(0x10), 'unknown_2'),
        (pint.uint32_t, 'flags'),               # 24
        (dyn.pointer(Node), 'firstChild'),      # 28
        (dyn.pointer(Node), 'lastChild')        # 2c
    ]


#attributes? how do we get to them?

class QualifiedName(pstruct.type):
    _fields_ = [
        (dyn.addr_t, '`vftable`'),
        (pint.uint32_t, '1'),
        (pint.uint32_t, '2'),
        (pint.uint32_t, '3'),
    ]

class AtomicString(pstruct.type):
    _fields_ = [
        (dyn.addr_t, '`vftable`'),
        (pint.uint32_t, 'length'), #4
        (lambda s: pointer(dyn.clone(pstr.wstring, length=int(s['length']))), 'string'),
    ]
    def get(self):
        return self['string'].get().load().get()

class Attribute(pstruct.type):
    _fields_ = [
        (dyn.addr_t, '`vftable`'),
        (pint.uint32_t, 'unknown'),
        (dyn.pointer(QualifiedName), 'm_name'),
        (dyn.pointer(AtomicString), 'm_value'), # 0x0c
    ]

class NamedNodeMap(pstruct.type):
    _fields_ = [
        (dyn.addr_t, '`vftable`'),
        (dyn.block(8), 'unknown'),
        (pint.uint32_t, 'm_attributes.length'), # c
        (dyn.pointer(Attribute), 'm_attributes'), #10
    ]

class HTMLStackElem(pstruct.type): pass
HTMLStackElem._fields_ = [
        (dyn.pointer(AtomicString), 'ElementName'),
        (pint.uint32_t, 'level'),
        (dyn.pointer(pstr.szwstring), 'tagName*'),
        (dyn.pointer(Node), 'Node*'),
        (pint.uint32_t, 'unknown'),
        (dyn.pointer(HTMLStackElem), 'next'),
    ]


if __name__ == '__main__':
    import ali,webkit
    r = ali.open(0x944).load()

    reload(webkit)
    v = r.newtype(webkit.Node)
    v.setoffset(r['Eax'])
    v.load()

    out = file('c:/blah.dot','wt')
    out.write('graph test {\n')
    parent = v.getroot()
    parent.render_dot(out)
    out.write('}\n')
    out.close()
