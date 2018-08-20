"""
document

decorators used to assist with auto-documentation
"""

def parameters(**kwargs):
    def parameters(F):
        return F
    return parameters

def aliases(*args):
    def aliases(F):
        return F
    return aliases

def details(docstring):
    def details(F):
        return F
    return details

def namespace(F):
    return F

def classdef(F):
    return F
