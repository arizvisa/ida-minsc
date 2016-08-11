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

# scope for execution queue and hooks
ui.queue.__start_ida__(), ui.hook.__start_ida__()
map(__import__('atexit').register, (ui.queue.__stop_ida__, ui.hook.__stop_ida__))

# start and stop execution queue when database is open or closed
ui.hook.idp.add('init', ui.queue.__open_database__, 0)
ui.hook.idp.add('term', ui.queue.__close_database__, 0)

# update database state when ida's queues enter various states
ui.hook.idp.add('init', __import__('hooks').on_init, 0)
ui.hook.idp.add('loader_finished', __import__('hooks').on_loaded, 0)
ui.hook.idp.add('auto_empty', __import__('hooks').on_ready, 0)

# setup default integer types for the typemapper once the loader figures everything out
ui.hook.idp.add('loader_finished', __import__('internal').interface.typemap.__loader_finished__, 0)

# create the tagcache netnode in any new database
ui.hook.idp.add('init', __import__('internal').comment.tagging.__init_tagcache__, 0)

# hook any user-entered comments so that they update the tagcache
[ ui.hook.idb.add(n, __import__('hooks').noapi, 40) for n in ('changing_cmt','cmt_changed','changing_area_cmt', 'area_cmt_changed') ]

ui.hook.idp.add('init', __import__('hooks').address.database_init, 45)
ui.hook.idp.add('init', __import__('hooks').globals.database_init, 45)
ui.hook.idb.add('changing_cmt', __import__('hooks').address.changing, 45)
ui.hook.idb.add('cmt_changed', __import__('hooks').address.changed, 45)
ui.hook.idb.add('changing_area_cmt', __import__('hooks').globals.changing, 45)
ui.hook.idb.add('area_cmt_changed', __import__('hooks').globals.changed, 45)

# hook naming and extra comments to support implicit tags in the tagcache
ui.hook.idp.add('rename', __import__('hooks').rename, 40)
ui.hook.idb.add('extra_cmt_changed', __import__('hooks').extra_cmt_changed, 40)

# hook function creation/modification so they shuffle any tags between the differing tagcache types
[ ui.hook.idb.add(n, getattr(__import__('hooks'),n), 40) for n in ('thunk_func_created','func_tail_appended','removing_func_tail') ]
[ ui.hook.idp.add(n, getattr(__import__('hooks'),n), 40) for n in ('add_func','del_func','set_func_start','set_func_end') ]

# rebase the tagcache if the entire database was rebased.
ui.hook.idb.add('allsegs_moved', __import__('hooks').rebase, 50)

# prevent idapython from trying to write it's banner to the message window.
print_banner = lambda: None

#[ ui.hook.ui.add(n, __import__('hooks').notify(n), -100) for n in ('range','idcstop','idcstart','suspend','resume','term','ready_to_run') ]
#[ ui.hook.idp.add(n, __import__('hooks').notify(n), -100) for n in ('newfile','oldfile','savebase','closebase','init','term','newprc','newasm','loader_finished','loader') ]
#[ ui.hook.idp.add(n, __import__('hooks').notify(n), -100) for n in ('auto_empty','auto_queue_empty') ]
#[ ui.hook.idb.add(n, __import__('hooks').notify(n), -100) for n in ('thunk_func_created','func_tail_appended','removing_func_tail') ]
#[ ui.hook.idp.add(n, __import__('hooks').notify(n), -100) for n in ('add_func','del_func','set_func_start','set_func_end') ]
#ui.hook.idb.add('allsegs_moved', __import__('hooks').notify('allsegs_moved'), -100)
