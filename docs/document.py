"""
Document (mock) module

These module is only included to retain documentation for the different
decorators used by the document parser. These decorators are not actually
executed and exist only to provide hints to the document parser when
auto-generating the documentation.
"""

def parameters(**kwargs):
    """
    Takes an arbitrary number of keywords which represent the name of the
    decorated function's parameters. Each keyword's value contains an
    explanation for what the particular parameter does.
    """
    def parameters(F):
        return F
    return parameters

def aliases(*args):
    """
    Takes an arbitrary number of strings that describe what aliases the
    decorated function/namespace might have. When describing an alias,
    the full namespace to the target function must be included.
    """
    def aliases(F):
        return F
    return aliases

def details(docstring):
    """
    This decorator allows one to add more details to the auto-generated
    documentation for a function or class via the `docstring` parameter.
    This documentation can be single or multi-lined.
    """
    def details(F):
        return F
    return details

def namespace(F):
    """
    This decorator is used to mark a class definition as a namespace
    instead of an object. This will result in the auto-generated
    documentation including the full namespace when emitting each
    function's name.
    """
    return F

def classdef(F):
    """
    This decorator is used to mark a class definition as an object.
    When processing the methods and properties inside a class
    definition that is marked as an object, the "self" parameter
    will be automatically included and each method prototype will
    exclude the mention of the class name.
    """
    return F

def hidden(F):
    """
    This decorator is used to notify the documentation parser that
    the decorated function/class is not to be included in the
    generated documentation. This can be used to mark a function/class
    that is only defined temporally such as when the definition is
    overwritten later by a definition with the same name.
    """
    return F

def rename(name):
    """
    This decorator will allow one to rename a function/class definition
    when generating the documentation. When generating the documentation
    for a decorated function/class, its name will be set to `name`.
    """
    def rename(F):
        return F
    return rename
