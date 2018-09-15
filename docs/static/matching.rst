.. _matching-intro:

Matching/Filtering of IDA types
===============================

IDA exposes a number of types as lists that can be viewed within a window.
Although these lists can be interacted with, the only way a user has to
filter them is via doing text searches and this is moreso used for
navigation. When interacting with these types programmatically, there are
a number of ways that a user can implement to filter or match them.

However, this requires the user to implement these methods themselves,
which can potentially require time searching through documentation
in order to identify the required functionality in order to extract the
required properties to filter said types.

This project actually implements a number of these filtering methods to
avoid the user having to implement this themselves. This is done by providing
what are known as :ref:`matching-functions` for the various types that IDA exposes to
a user. These :ref:`matching-functions` let a user provide a keyword argument describing
the method to filter with which will then be used to return the filtered types
to the user.

Some examples of the common keyword arguments that are provided are:

+----------------------+----+----------------------------------------------------+
| :py:data:`address`   | -- | Match according to an address.                     |
+----------------------+----+----------------------------------------------------+
| :py:data:`name`      | -- | Match according to the exact name specified.       |
+----------------------+----+----------------------------------------------------+
| :py:data:`like`      | -- | Filter according to a glob being applied to a name |
+----------------------+----+----------------------------------------------------+
| :py:data:`regex`     | -- | Filter according to a regular-expression being     |
|                      |    | applied to a name.                                 |
+----------------------+----+----------------------------------------------------+
| :py:data:`predicate` | -- | Filtering according to a callable that critiques   |
|                      |    | the type returning true or false.                  |
+----------------------+----+----------------------------------------------------+

These keywords are then exposed to users via 3 general function styles. Each
matcher will typically provide functionality similar to the :py:func:`namespace.list`,
:py:func:`namespace.search`, and :py:func:`namespace.iterate` functions described
within this document. This can then be used to filter the various types in IDA
using one of the keywords that are supported by the :ref:`matching-functions` for
said type.

.. _matching-examples:

Examples
--------

Some of the matcher classes that are available can be found within the
:py:mod:`database` module, the :py:mod:`structure` and :py:mod:`enumeration`
modules, or the :py:mod:`segment` modules. Within the :py:mod:`database`
module, most of the :ref:`matching-functions` are defined within namespaces
and represent different things such as :py:class:`imports`, :py:class:`entries`,
:py:class:`names`, :py:class:`functions`, etc. It is recommended to review
the help for these modules in order to understand exactly what is provided.

To list all of the structures within the database::

   > struc.list()

To iterate through all the structures that begin with "my\_"::

   > for st in struc.iterate(like="my_*"): ...

To search for a function containing the address 0x401034::

   > f = db.functions.search(ea=0x401034)
   > print f

To iterate through all the structure members that match a regex to
search for unnamed fields::

   > st = struc.by(...)
   > for m in st.iterate(regex='field_.\*$')

.. _matching-functions:

Common matcher functions
------------------------

The 3 basic matcher functions typically have the following prototypes. Each of
these prototypes can take a keyword argument where the key specifies the type.
Typically there are also multicased versions of these functions that take a
single string as its argument. By default this function will be using the
:py:data:`like` keyword thus making its argument a glob. Please review the
related documentation for the full functionality of each matcher instance.

.. py:function:: namespace.list(**type)

   This function will list the matched types within the IDA console. Each row
   that is displayed will contain a summary of the type that has matched. This
   can then either be double-clicked on, or used to build another filter to
   then match with another function.

   :param type: a keyword argument representing the type of match to perform and
                what value to match it against

.. py:function:: namespace.search(**type)

   Once a desired type has been determined, this function can then be used to
   return the first result that matches. If more than one result is returned,
   then this function will warn the user the number of results that matched,
   whilst still returning the very first one.

   :param type: a keyword argument representing the type of match to perform and
                what value to match it against
   :return: the first item that was matched

.. py:function:: namespace.iterate(**type)

   When a user wishes to enumerate all of the matches of a particular type, they
   will need to use this function. Once given a keyword and value to match with,
   this function will iterate through all of the results that are available. These
   results will be the core type that the matcher is filtering.

   :param type: a keyword argument representing the type of match to perform and
                what value to match it against
   :return: an iterator that yields each matched result
