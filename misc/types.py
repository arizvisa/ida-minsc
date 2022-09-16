"""
Types module (internal)

This internal module contains each of the types that are available
for usage when matching against a particular implementation of a
multicased function. This is necessary as some of the different
variations of Python will change their names or remove their
definition entirely.
"""

import six, types
from types import *

none = None.__class__
bool = bool
bytes = b''.__class__
string = six.string_types
integer = six.integer_types
float = float
ellipsis = Ellipsis.__class__

# Py2 imports are wonky when the names clash, so we use dunder import
# to work around Py2's busted import implementation.
code = __import__('types').CodeType
function = __import__('types').FunctionType
method = __import__('types').MethodType

staticmethod = staticmethod
classmethod = classmethod
descriptor = staticmethod, classmethod

tuple = tuple
list = list
set = set
dictionary = dict
ordered = tuple, list
unordered = ordered, set

type = type
object = object
instance = (object, types.InstanceType) if hasattr(types, 'InstanceType') else (object,)
class_t = (type, types.ClassType) if hasattr(types, 'ClassType') else (type,)

slice = slice
bytearray = bytearray
memoryview = memoryview
callable = callable
