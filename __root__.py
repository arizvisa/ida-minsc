## ida-python specific modules
import _idaapi as idaapi,ida

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

ui.hook.ui.add('database_inited', __import__('internal').interface.typemap.__database_inited__, 0)
