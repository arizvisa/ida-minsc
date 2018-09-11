# -*- coding: utf-8 -*-
#
# ida-minsc documentation build configuration file, created by
# sphinx-quickstart on Fri Mar  2 11:49:24 2018.

import sys, os
# needs_sphinx = '1.0'

## General information about the project.
project = u'ida-minsc'
copyright = u'2010-2018, Ali Rizvi-Santiago'
author = u'Ali Rizvi-Santiago'
version = u''
release = u''

## Paths and sources
templates_path = ['templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

source_suffix = [ '.rst', '.md' ]

extensions = [
    #'sphinx.ext.githubpages',
]

## Python specifics
primary_domain = 'py'
highlight_language = 'python'
pygments_style = 'sphinx'

todo_include_todos = False

## The master toctree document.
language = None
master_doc = 'index'

## HTML configuration
html_theme = 'classic'
# html_theme_options = {}
# html_static_path = ['html-static']

#html_sidebars = {
#    '**': [
#        'about.html',
#        'navigation.html',
#        'relations.html',  # needs 'show_related': True theme option to display
#        'searchbox.html',
#        'donate.html',
#    ]
#}


## HTMLHelp configuration
htmlhelp_basename = 'ida-minsc.doc'

## LaTeX configuration
latex_elements = {
    # 'papersize': 'letterpaper',
    # 'pointsize': '10pt',
    # 'preamble': '',
    # 'figure_align': 'htbp',
}

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title, author, documentclass [howto, manual, or own class]).
latex_documents = [
    (master_doc, 'ida-minsc.tex', u'ida-minsc Documentation', u'Ali Rizvi-Santiago', 'manual'),
]


## Manpage configuration
# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    (master_doc, 'ida-minsc', u'ida-minsc Documentation', [author], 1)
]


## Texinfo configuration
# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author, dir menu entry, description, category)
texinfo_documents = [
    (master_doc, 'ida-minsc', u'ida-minsc Documentation', author, 'ida-minsc', 'One line description of project.', 'Miscellaneous'),
]
