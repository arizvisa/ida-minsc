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


#####

from ali import *
import database

class analyze_xrefs(analyze):


  def enter(self, pc, **options):
    options['database'].context.set(pc, name=database.name(pc))
    #print 'enter'
    # get xrefs to this function head
    xrefs_to = database.cxup(pc)

    # save to the stash
    #state.store('xrefs-to', (pc, xrefs_to))

    # add function to the database
    for x in xrefs_to:
      xref_top = function.top(x)
      options['database'].context.edge((xref_top, x), (pc,pc))
    
    # create edges? or stash to the state.store

    return


  def iterate(self, state, pc, insn, **options):
    #print 'iterate'

    # if its a call, get the xrefs from it
    if ia32.isCall(insn):
      xrefs_from = database.cxdown(pc)

      func_top = function.top(pc)
      for x in xrefs_from:
        options['database'].context.edge((func_top, pc), (x, x))

      # save to the stash
      #state.store('xrefs-from', (pc, xrefs_from))

    return


def go(all=False):

  fname = r'C:\tmp\zomg.db'

  import sqlite3
  import store

  """
  s = sqlite3.connect(fname)
  admin = store.deploy.sql(s)
  admin.create_schema()

  u = store.interface.sql(s)

  options = {}
  options['database'] = u


  if all:
    all_funcs = database.functions()
  else:
    all_funcs = [ea]


  for ea in all_funcs:

    analyza = analyze_xrefs()

    try:
      analyza.enter(ea, **options)

      collector = analyza.iterate
      result = collect(ea, 0, [collector], **options)

    except ValueError:
      print "0x%08x - failed to process node." % ea

    #analyza.exit(ea, **options)

    options['database'].commit()

  print "Succesfully processed %d functions." % len(all_funcs) 

  s.close()

  """

  import RefTree
  tree = RefTree.RefTree(fname)
  #tree.add_func(0x7C901000)
  #tree.add_func(0x7C91B1BF)
  tree.add_func(2089816598)
  tree.add_func(0x7C91EA7B)
  print tree.makeTrees()

  #tree.



  
