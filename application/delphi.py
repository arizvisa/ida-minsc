"""
Delphi module

This module exposes some basic tools for working with a database built against
a delphi target. These tools are simple things that can help with automating
the creation of strings or other types of data structures that one may find.
"""

import functools, itertools, types, builtins, operator, six
import database as db, function as func, instruction as ins, structure as struc

import logging, string
from internal import utils
logging = logging.getLogger(__name__)

def string(ea):
    '''Convert the string defined by IDA at the address `ea` into a delphi-style string and return its length.'''
    if db.get.i.uint32_t(ea - 8) == 0xffffffff:
        db.set.undefined(ea)
        db.set.integer.dword(ea - 8)
        cb = db.set.string(ea - 4, type=idaapi.STRTYPE_LEN4)
        try:
            al = db.set.align(ea - 4 + cb, alignment=8)
        except TypeError:
            al = db.set.align(ea - 4 + cb, alignment=4)
        return 4 + cb + al
    logging.warning(u"{:s}.string({:#x}): The data at address {:#x} is not a properly prefixed delphi string.".format(__name__, ea, ea - 8))
    return 0
