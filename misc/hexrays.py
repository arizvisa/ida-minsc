r"""
Hexrays module (internal)

This module wraps a number of features provided by the Hex-Rays decompiler
so that it can be dumbed down a bit. This module is used internally and thus
doesn't provide anything that a user should find useful. Nonetheless, we
document this to allow curious individuals to determine how it all works.
"""

import functools, operator, itertools, logging
import idaapi, database, internal
from internal import utils, interface, types, exceptions

### this closure returns a descriptor which will give priority to one object when fetching a
### specific attribute, and fall back to the other object when if the attribute was not found.
def missing_descriptor(module, missing):
    """Return a descriptor that attempts to fetch an attribute from the given `module`, or returns the one from `missing`."

    If a callable ends up being fetched from `missing`, the callable is executed with the desired module and attribute.
    """
    class descriptor(object):
        def __init__(self, attribute):
            if hasattr(module, attribute):
                self.__result__ = getattr(module, attribute)
            elif hasattr(missing, attribute) and callable(getattr(missing, attribute)):
                self.__result__ = getattr(missing, attribute)(module, attribute)
            else:
                self.__result__ = getattr(missing, attribute)
            return
        def __get__(self, obj, type=None):
            return self.__result__
    return descriptor

def new_partial_api(name, object, descriptor):
    '''Create a new type with the specified `name` that contains the specified `descriptor` for each attribute inside `object`.'''
    namespace = { attribute : descriptor(attribute) for attribute, _ in object.__dict__.items() if not attribute.startswith('_') }
    return type(name, (object,), namespace)

def missing_callable(object, attribute):
    '''Return a callable for ``missing_descriptor`` that will raise an ``UnsupportedCapability`` exception when called.'''
    def missing_callable(*args, **kwargs):
        '''This api is inaccessible either due to an error during import or is missing from the "ida_hexrays" module.'''
        raise internal.exceptions.UnsupportedCapability(u"The requested function \"{:s}\" is currently inaccessible or is missing.".format(utils.string.escape('.'.join([object.__name__, attribute]), '"')))
    return missing_callable

def simulate_missing_callable(level, Fcallable):
    '''Return a callable for ``missing_descriptor`` that will log an ``UnsupportedCapability`` exception and then call the given `callable` to return its result.'''
    def simulate_missing_callable(object, attribute):
        '''This api is inaccessible either due to an error during import or is missing from the "ida_hexrays" module.'''
        def simulate_missing_callable(Fcallable, Fraise_exception, *args, **kwargs):
            try:
                discard = Fraise_exception(*args, **kwargs)
                raise AssertionError(u"An unexpected error has occurred when trying to raise an exception for the missing attribute \"{:s}\".".format(utils.string.escape('.'.join([object.__name__, attribute]), '"')))
            except internal.exceptions.UnsupportedCapability as E:
                logging.log(level, u"Simulating the requested function \"{:s}\" due to it being currently inaccessible or missing.".format(utils.string.escape('.'.join([object.__name__, attribute]), '"')))
            return Fcallable(*args, **kwargs)
        return functools.partial(simulate_missing_callable, Fcallable, missing_callable(object, attribute))
    return simulate_missing_callable

def missing_callable(object, attribute):
    '''Return a callable for ``missing_descriptor`` that will raise an ``UnsupportedCapability`` exception when called.'''
    def missing_callable(*args, **kwargs):
        '''This api is inaccessible either due to an error during import or is missing from the "ida_hexrays" module.'''
        raise internal.exceptions.UnsupportedCapability(u"The requested function \"{:s}\" is currently inaccessible or is missing.".format(utils.string.escape('.'.join([object.__name__, attribute]), '"')))
    return missing_callable

def use_callable(callable):
    '''Return a callable that when used by ``missing_descriptor``, will return the specified `callable`.'''
    def use_callable(object, attribute):
        return callable
    return use_callable

def missing_class(module, attribute):
    '''Return a class for ``missing_descriptor`` that will raise an ``UnsupportedCapability`` exception when used.'''
    class missing_class(object):
        def __new__(*args, **kwargs):
            '''This api is inaccessible either due to an error during import or is missing from the "ida_hexrays" module.'''
            raise internal.exceptions.UnsupportedCapability(u"The requested class \"{:s}\" is currently inaccessible or is missing.".format(utils.string.escape('.'.join([module.__name__, attribute]), '"')))
        __slots__ = ()
    return missing_class

def use_class(type):
    '''Return a callable that when used by ``missing_descriptor``, will return the specified `type`.'''
    def use_class(object, attribute):
        return type
    return use_class

### This class is to provide a backing namespace for things missing from the "ida_hexrays" module.
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

# Try and import the module. If we can, then all the attributes from our descriptor
# should end up being forwarded directly to the module as they originally were.
try:
    hexrays_descriptor = missing_descriptor(__import__('ida_hexrays'), ida_hexrays_template)

# If we couldn't import the "ida_hexrays" module, then this descriptor acts as a
# compatibility layer that allows users of the module to still be compiled (evaluated).
except ImportError:
    hexrays_descriptor = missing_descriptor(object, ida_hexrays_template)

# Use the template to generate a new object that wraps the "ida_hexrays" module.
ida_hexrays = new_partial_api('ida_hexrays', ida_hexrays_template, hexrays_descriptor)

# ...and then delete all the things that we don't need anymore.
del(ida_hexrays_template)
del(hexrays_descriptor)
del(new_partial_api)
