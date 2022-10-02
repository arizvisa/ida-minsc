r"""
Hexrays module (internal)

This module wraps a number of features provided by the Hex-Rays decompiler
so that it can be dumbed down a bit. This module is used internally and thus
doesn't provide anything that a user should find useful. Nonetheless, we
document this to allow curious individuals to determine how it all works.
"""

import idaapi, database, internal
from internal import utils, interface, types, exceptions

### this closure returns a descriptor which will expose the attributes
### for a module and make them accessible whether they exist or not.
def default_descriptor(module, error):
    class descriptor(object):
        def __init__(self, attribute, default):
            if hasattr(module, attribute):
                self.__result__ = getattr(module, attribute)
            elif callable(default):
                self.__result__ = error
            else:
                self.__result__ = default
            return
        def __get__(self, obj, type=None):
            return self.__result__
    return descriptor

def new_partial_api(name, object, descriptor):
    '''Create a new type with the specified `name` that contains the specified `descriptor` for each attribute inside `object`.'''
    namespace = { attribute : descriptor(attribute, value) for attribute, value in object.__dict__.items() if not attribute.startswith('__') }
    return type('ida_hexrays', (object,), namespace)

def missing_attribute(*args, **kwargs):
    '''This api is inaccessible either due to an error during import or is missing from the "ida_hexrays" module.'''
    raise internal.exceptions.UnsupportedCapability(u'The requested capability is currently inaccessible or is missing.')

# Try and import the module. If we can, then all the attributes from our descriptor
# should end up being forwarded directly to the module as they originally were.
try:
    hexrays_descriptor = default_descriptor(__import__('ida_hexrays'), missing_attribute)

# If we couldn't import the "ida_hexrays" module, then this descriptor acts as
# a compatibility layer that allows ths module to still be compiled (evaluated).
except ImportError:
    hexrays_descriptor = default_descriptor(object, missing_attribute)

else:
    del(missing_attribute)
    del(default_descriptor)

### this object is simply for capturing stuff that we need from "ida_hexrays".
class ida_hexrays_template(object):
    """
    This class is just a template for the "ida_hexrays" module and
    is used to generate a namespace that can be substitued in place
    of the module in case there's any attrbutes that might be missing.
    """
    MMIDX_GLBLOW, MMIDX_GLBHIGH = 0x0, 0x5

    ___ = callable
    mop_t, minsn_t, mop_z = ___, ___, 0x0
    mop_r, mop_n, mop_str = 0x1, 0x2, 0x3
    mop_d, mop_S, mop_v   = 0x4, 0x5, 0x6
    mop_b, mop_f, mop_l   = 0x7, 0x8, 0x9
    mop_a, mop_h, mop_c   = 0xa, 0xb, 0xc
    mop_fn, mop_p, mop_sc = 0xd, 0xe, 0xf

# use the template to generate a new object that wraps the "ida_hexrays" module.
ida_hexrays = new_partial_api('ida_hexrays', ida_hexrays_template, hexrays_descriptor)

# ...and then delete all the things that we don't need anymore.
del(ida_hexrays_template)
del(hexrays_descriptor)
del(new_partial_api)
