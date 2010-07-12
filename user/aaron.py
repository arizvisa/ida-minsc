import database
from idc import *
from idautils import *

def FetchLeafs():
    '''aaron's leaf fetching database thing that searches for E8'''
    ea = SegByName(".text")
    end = SegEnd(ea)

#    allFuncs = list(Functions(ea, end))
    allFuncs = database.functions()

    while True:
      if ea > end:
        break

      call = FindBinary(ea, SEARCH_DOWN, "E8", 16)

      if call == -1:
        print "wtf -1\n"
        break

      funcStart = GetFunctionAttr(call, FUNCATTR_START)

      try:
        allFuncs.remove(funcStart)
        ea = GetFunctionAttr(call, FUNCATTR_END)
      except ValueError:
        ea = call+1
        pass

    return allFuncs
