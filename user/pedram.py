import database
from idaapi import Choose
from idc import Jump

from idc import GetFunctionAttr,FUNCATTR_START
from idautils import CodeRefsTo
def FetchLeafs():
    '''pedram's leaf fetching database thing that uses CodeRefsTo'''
    all = database.functions()
    leaf = all[:]

    for ea in all:
        for xref in CodeRefsTo(ea, 1):
            func = GetFunctionAttr(xref, FUNCATTR_START)
            try:
                leaf.remove(func)
            except (KeyError, ValueError), e:
                # already removed.
                pass

    return leaf                

def Output (name, list, width=-1):
 class __chooser (Choose):
  def __init__ (self, name, list, width):
   Choose.__init__(self, list, name)
   self.width = width
 
  def enter (self, n):
   print "[%d] %s" % (n, self.list[n-1])
   Jump(int(self.list[n-1].split(":")[0], 16))

 return __chooser(name, list, width).choose()

if __name__ == '__test__':  # heh
    ep   = GetEntryOrdinal(0)
    num  = 500
    l    = []
    name = "First %d heads" % num

    for h in Heads(ep, ep+num):
        l.append("%08x: %s" % (h, GetDisasm(h)))

    output(name, l)

