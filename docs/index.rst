.. _start:

Welcome to IDA-Minsc
====================

.. container:: top-margin

   .. container ::

      IDA-minsc is a plugin for IDA Pro that assists a user with scripting the
      IDAPython plugin that is bundled with the disassembler. This plugin groups the
      different aspects of the IDAPython API into a simpler format which allows a
      reverse engineer to script different aspects of their work with very little
      investment.

   .. container:: right-floating

      .. image:: _images/hamster.svg
         :class: logo-content
         :alt: hamsters for everyone

A number of concepts are introduced such as a tagging system, support for
multicased functions, and filtering with the intention that most search
and annotation issues can be performed with just a few lines of code. This
should enable a user to write quick, hacky, temporary code that can be used
to augment their reversing endeavors without distraction.

This plugin is dependant upon IDAPython with Python 2.x, and supports all of
the different platforms the IDA supports which includes Windows, Linux, and
MacOS. At the present time, only IDA 6.8 up till IDA 7.4 are currently
supported.

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
