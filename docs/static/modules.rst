=======
Modules
=======

Each of the modules exposed by this project are suggested by the author
to be thought of as a namespace that contains functions related to the
module that they're a part of. There are a number of modules which are
exposed by default whereas others such as :py:mod:`tools` are available
via the "tools" namespace.

Available modules
-----------------

.. toctree::
   :name: moduletoc
   :maxdepth: 1
   :caption: These modules compose the majority of this project and provide
             various tools that allow one to interact with the IDA database.
             These are each named according to the context they interact with.

   modules/database
   modules/enumeration
   modules/function
   modules/instruction
   modules/segment
   modules/structure

Miscellaneous modules
---------------------

.. toctree::
   :name: misctoc
   :maxdepth: 1
   :caption: These miscellaneous modules expose things that a user might
             care to interact with. Eventually some of these modules
             will be migrated into the base modules.

   modules/misc-ui

Tools module
------------

.. toctree::
   :name: toolstoc
   :maxdepth: 1
   :caption: These modules are accessed via the `tools` namespace and provide
             higher-level abstractions that allow one to interact with some of
             the features provided by the plugin or to interact with the database
             in soem generalized way.

   modules/tools-general
   modules/tools-tags
   modules/tools-tagfix
