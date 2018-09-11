.. _pythontyping-intro:

Types in IDA
============

In IDA, a core feature is the ability to apply types to either operands,
addresses, structure members, etc. This is a very powerful capability
and is one of the more important features of IDA Pro. By doing this,
this allows a reverse-engineer to identify the relationships between
the types used by instruction operands and global variables. This is
normally exposed to the user by various commands or hotkeys.

IDAPython and the IDA SDK exposes an API to allow a user to programmatically
apply and retrieve type information from the various places a type might
have been applied to. There are a variety of functions that do this, and a
number of enumerations, flags, and constants that allow one to customize
their types.

Unfortunately, using these APIs is likely to get complex as one will
need to identify which function to use combined with determining which
constants or flags to represent the type they wish to apply.

This project attempts to simplify this by introducing a concept referred
to as "Pythonic" types. This is done by dual-using the semantics of the
types available in the Python language [:ref:`1<pythontyping-references>`]
to determine the correct constants and flags needed by IDA.

.. _pythontyping-references:
.. rubric:: Referencees

1. `The Python Programming Language <https://www.python.org/>`_

.. _pythontyping-format:

---------------------
Pythonic types format
---------------------

There are a number of places within this project that allow a user to
display or apply a type. One such place where this is allowed is for
a structure member. Although structure members in IDA contain numerous
attributes one of them is the type field which can be used to assign
a Pythonic type into.

AS mentioned before, Pythonic types utilise the semantics of the more
commonly known types in Python in order to enable the user of this
project to describe the type of a receiver of type information such
as a structure's field. A pythonic type is composed of what's referred
to as a container type, and inside the container type is the element
type.

Describing the container
************************

There are two types of container types, these are the tuple which uses
"(" and ")" to group types, and the list which uses "[ and "]" to
group the type. A tuple is produces the semantics of an atomic type
and is just used to specify the size of the type. A list, however, is
used to describe an array and thus is used to specify the number of
elements in the array.

When grouping a Pythonic type with either of these, the first element is
always the type or class, and the second element is referred to as the
size or count. If neither of these container types are specified, then
the default size for the core type will be assumed.

A few examples of how to describe an atomic type for an imaginary type
:py:obj:`t` can be::

   > res = (t, 3)  # 3 bytes in size
   > res = (t, 8)  # 8 bytes in size
   > res = t       # 4 bytes on 32-bit architectures, 8 bytes on 64-bit

A few examples of using a list to describe an array for an imaginary
type :py:obj:`t` can be::

   > res = [t, 4]          # 4 element array of a default sized 't'
   > res = [(t, 2), 10]    # 10 element array of a 't' that is 2 bytes in size
   > res = [(t, 8), 4]     # 4 element array of a 't' that is 8 bytes in size

Describing the core type
************************

The core type is considered an atomic type and is simply composed of various
keywords available in Python that are used to construct objects. It is important
to recognize that these are used literally as keywords and they're not intended to
retain any kind of state.

Any one of the following Python types and functions can be used to represent a
type that will be transformed into IDA's format.

- :py:obj:`int` or :py:obj:`long` - an integer type (``idaapi.FF_BYTE``, ``idaapi.FF_WORD``, ``idaapi.FF_DWORD``, etc.)
- :py:obj:`chr` or :py:obj:`str` - a character/string type (``idaapi.FF_STRLIT``, etc.)
- :py:obj:`float` - a floating point type (``idaapi.FF_FLOAT``, ``idaapi.FF_DOUBLE``, etc.)
- :py:obj:`type` - a pointer type (``idaapi.FF_OFF*``, etc.)
- :py:obj:`None` - an alignment type (``idaapi.FF_ALIGN``)
- an instance of a :py:class:`structure_t` - a structure as retrieved by the :py:mod:`structure` module using :py:func:`structure.by` or similar

Using these common keywords as types allows one to not have to remember or
search through documentation for the correct flags to apply to IDA. For
most general purposes this should suffice.

However, if a user chooses to not use this interface, most of the functions
that take pythonic types are also capable of taking an integer. This integer
is the manually combined flags that represent an IDA type. It is however
suggested by the author that the user familiarize themselves with the way
that Pythonic types appear in order to comprehend some of the output of
functions that return their type in this format.

.. _pythontyping-examples-types:

--------
Examples
--------

By using a container type combined with a core type, a vast number of IDA
types can be represented. This allows a user to quickly identify what type
is being represented without having to test any bits within the integer
representing the type. Some examples of describing an atomic type in this format
follows.

- ``(int, 4)`` -- A 4 byte sized integer (dword)
- ``(int, 8)`` -- A 2 byte sized integer (qword)
- ``(int, 1)`` -- A single byte sized integer (byte)
- ``(float, 4)`` -- A 4 byte sized floating point number (single)
- ``chr`` -- A single byte sized character or string
- ``int`` -- A default sized integer (dword on 32-bit, qword on 64-bit)
- ``(None, 8)`` -- An alignment to a multiple of 8
- ``(str, 10)`` or ``(chr, 10)`` -- A 10 character string


Some examples of using a list to describe an array of some particular element
follows as well.

- ``[(int, 4), 8]`` -- An 8 element array of 4-byte integers (dwords)
- ``[float, 32]`` -- A 32 element array of default-sized floats
- ``[str, 256]`` -- A 256-element string

If a instance of :py:class:`structure_t` is desired to be used, this can be
treated as an atomic type. Usage of this, however, does not allow a user to
size the structure using the "(" and ")" grouping operators. This does, though,
allow a user to specify a :py:class:`structure_t` as an array such as via
the following:

- ``[mystruc, 6]`` -- if :py:obj:`mystruc` is an instance of :py:class:`structure_t`, then this would represent a 6 element array.
- ``[mystruc, 1]`` -- A single element array of :py:obj:`mystruc`

.. _pythontyping-examples-usage:

-----------------
Examples -- Usage
-----------------

There are a number of places that Pythonic types are used, however the most
common place is within structure members via the :py:attr:`type` attribute.
The following examples will demonstrate how to use pythonic types against
a structure member.

First, a structure will need to be identified and then a member which contains
a type will need to be fetched::

   > st = structure.search(like='*mystruc*')
   > m = st.members[4]

Output the type of the 4th member within the structure::

   > print m.type
   [int, 6]

Modify the type of the 4th member to be the same number of bytes::

   > m.type = [(int, 1), 24]     # 6 * 4

Shrink the member down to just a 16-bit integer::

   > m.type = (int, 2)

Change the member's type into a particular :py:class:`structure_t`::

   > st = structure.search('*someotherstructure*')
   > m.type = st

Modify the member's type so that it represents a 6 element array::

   > m.type = [st, 6]

Modify the member's type so that its a 3 element array of 8 byte floating point numbers (double)::

   > m.type = [(float, 8), 3]

