.. _start:

Welcome to IDA-Minsc
====================

.. container:: top-margin

   .. container ::

      IDA-Minsc is a plugin for IDA Pro that assists a user with scripting the
      IDAPython plugin that is bundled with the disassembler. This plugin groups the
      different aspects of the IDAPython API into a simpler format which allows a
      reverse engineer to script different aspects of their work with very little
      investment.

   .. container:: right-floating

      .. image:: _images/hamster.svg
         :class: logo-content
         :alt: hamsters for everyone

A number of capabilities are introduced such as an indexed tagging system,
support for multi-case functions which utilize pattern matching based on the
parameter type, and filtering with the intention that most search and annotation
tasks can (and should be) performed with just a few lines of Python. This should
enable a user to write quick, temporary scripts that can be used to augment
their reversing endeavors for exchanging information with other instances of
Python be it in a debugger or running standalone.

This plugin is (of course) dependent upon IDAPython, and supports each of the
platforms that IDA supports which includes Windows, Linux, and MacOS. This
also implies that both IDA Headless and its text user interface (based on
Turbo Vision) is also still usable.

If your instance of IDA was not installed with Python, or you wish to switch
between Python 3.x or the Python 2.x series, then please refer to the
instructions at section :ref:`1.6.2<install-downgrade>` for how to change the
Python runtime that IDAPython uses for your installation. At the present time,
only IDA Pro 6.8 to IDA 7.7.220125 are currently supported with Python v3.9.13.

Table of Contents
=================

.. toctree::
   :name: mastertoc
   :numbered:
   :maxdepth: 2

   install
   concepts
   modules
   tutorials

Index
=====

* :ref:`modindex`
* :ref:`genindex`
