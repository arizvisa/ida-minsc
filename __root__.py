## ida-python specific modules
import idaapi,ida

## contextual modules
import segment,database,function,instruction
import structure,enum

import database as db,function as func,instruction as ins,structure as struc

# default logging that displays any info
__import__('logging').root.level = __import__('logging').INFO

# shortcuts
h,top,go,goof = database.h,func.top,database.go,database.goof
hex = lambda n: '{:x}'.format(n)

import tools,ui
from tools import remote

import custom,app

# setup default integer types for the typemapper
ui.hook.ui.add('database_inited', __import__('internal').interface.typemap.__database_inited__, 0)

# create the tagcache netnode in the database
ui.hook.ui.add('database_inited', __import__('internal').comment.tagging.__database_inited__, 0)

# hook comments so that they update the tagcache
[ ui.hook.idb.add(n, __import__('internal').interface.hook.noapi, -1) for n in ('changing_cmt','cmt_changed','changing_area_cmt', 'area_cmt_changed') ]

ui.hook.idb.add('changing_cmt', __import__('internal').comment.address_hook.changing, 0)
ui.hook.idb.add('cmt_changed', __import__('internal').comment.address_hook.changed, 0)
ui.hook.idb.add('changing_area_cmt', __import__('internal').comment.global_hook.changing, 0)
ui.hook.idb.add('area_cmt_changed', __import__('internal').comment.global_hook.changed, 0)

# hook naming and extra comments to update the cache with their implicit tags
ui.hook.idp.add('rename', __import__('internal').interface.hook.rename)
#ui.hook.idb.add('extra_cmt_changed', __import__('internal').interface.hook.extra_cmt_changed)

print_banner = lambda: None
