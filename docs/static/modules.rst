=======
Modules
=======

Each of the modules exposed by this project are suggested by the author
to be thought of as a namespace that contains functions related to the
module that they're a part of. There are a number of modules which are
exposed by default whereas others such as :py:mod:`custom` are available
via the "custom" namespace.

Available modules
-----------------

.. toctree::
   :name: moduletoc
   :maxdepth: 1
   :caption: These modules compose the majority of this project and provide
             various tools that allow one to interact with the IDA database.
             These are each named according to the context they interact with.

   database
   enumeration
   function
   instruction
   segment
   structure

Miscellaneous modules
---------------------

.. toctree::
   :name: misctoc
   :maxdepth: 1
   :caption: These miscellaneous modules expose things that a user might
             care to interact with. Eventually some of these modules
             will be migrated into the base modules.

   ui
   tools

Custom modules
--------------

.. toctree::
   :name: customtoc
   :maxdepth: 1
   :caption: These custom modules are accessed via the `custom` namespace and
             allow one to interact with some of the things that are provided
             by this project.

   tags
   tagfix
