Matching/Filtering of IDA types
===============================

IDA exposes a number of types as lists that can be viewed within a window.
Although these lists can be interacted with, the only way a user has to
filter them is via doing text searches and this is moreso used for
navigating. When interacting with these types programmatically, there are
a number of ways that a user can implement to filter these or match them.

However, this requires the user to implement these methods themselves
which can potentially require time consuming searching through documentation
in order to identify the required properties, or functions necessary to
extract the required properties to filter.

This project actually implements a number of these filtering methods to
avoid the user having to implement this themselves. This is done by providing
what are known as :ref:`matchers` for the various types that IDA exposes to
them. These :ref:`matchers` let a user provide a keyword argument describing
the method to filter with which will then be returned to the user in various
forms.

Some examples of the common keyword arguments that are provided are:

   `address` - Match according to an address
   `name` - Match according to an exact name
   `like` - Match according to a glob
   `regex` - Match according to a regular-expression
   `predicate` - Match according to a callable

These :ref:`matcher` keywords arethen  exposed to users via 3 primary functions.
The most common ones that this project uses, are :py:func:`namespace.list`,
:py:func:`namespace.search`, and :py:func:`namespace.iterate`. These can then
be used to filter any of the types in IDA that are supposed by :ref:`matchers`.

Examples
--------

Some of the matcher classes that are available can be found within the :py:mod:`database`
module, the :py:mod:`structure` and :py:mod:`enumeration` modules, or the :py:mod:`segment`
modules. Within the :py:mod:`database` module, most of the :ref:`matchers` are
defined within namespaces and represent different things such as imports, exports,
names, functions, etc.

To list all of the structures within the database::

   > struc.list()

To iterate through all the structures that begin with "my_"::

   > for st in struc.iterate(like="my_*"): ...

To search for a function containing the address 0x401034::

   > f = db.functions.search(ea=0x401034)
   > print f

To iterate through all the structure members that match a regex to
search for unnamed fields::

   > st = struc.by(...)
   > for m in st.iterate(regex='field_.\*$')

Common matcher functions
------------------------

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
   then this function will warn the user the number of results that matched
   whilst still returning the very first one.

   :param type: a keyword argument representing the type of match to perform and
                what value to match it against

.. py:function:: namespace.iterate(**type)

   When a user wishes to enumerate all of the matches of a particular type, they
   will need to use this function. Once given a keyword and value to match with,
   this function will iterate through all of the results that are available. These
   results will be the core type that the :ref:`matcher` is filtering.

   :param type: a keyword argument representing the type of match to perform and
                what value to match it against
