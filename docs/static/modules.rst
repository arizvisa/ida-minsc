=========
IDA-Minsc
=========

Aenean placerat orci et neque porta, nec commodo ante vehicula. Praesent
rutrum suscipit placerat. Aliquam justo felis, venenatis sit amet
consectetur eget, sagittis in eros. Maecenas a neque mollis, pharetra
dolor in, aliquam ligula. Morbi pulvinar eleifend erat, id semper purus
pretium ac. Praesent id ex orci. Nullam at sagittis erat. Vivamus feugiat
enim diam, sit amet rutrum tellus maximus ut.

Concepts
--------
.. toctree::
   multicase
   tagging
   matching
   combinators
   pythontyping

Available modules
-----------------

.. toctree::
   :name: mastertoc
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
