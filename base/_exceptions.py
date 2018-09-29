import exceptions as E

class MissingTagError(E.KeyError):
    """
    The requested tag at the specified address does not exist.
    """

class MissingFunctionTagError(MissingTagError):
    """
    The requested tag for the specified function does not exist.
    """

class MissingMethodError(E.NotImplementedError):
    """
    A method belonging to a superclass that is required to be overloaded was called.
    """

class UnsupportedVersion(E.NotImplementedError):
    """
    This functionality is not supported on the current version of IDA.
    """

class UnsupportedCapability(E.NotImplementedError, E.EnvironmentError):
    """
    An unexpected or unsupported capability was specified.
    """

class ResultMissingError(E.LookupError):
    """
    The requested item is missing from its results.
    """

class SearchResultsError(ResultMissingError):
    """
    No results were found.
    """

class DisassemblerError(E.EnvironmentError):
    """
    An api call has thrown an error or was unsuccessful.
    """

class MissingTypeOrAttribute(E.TypeError):
    """
    The specified location is missing some specific attribute or type.
    """

class InvalidTypeOrValueError(E.TypeError, E.ValueError):
    """
    An invalid value or type was specified.
    """

class InvalidParameterError(InvalidTypeOrValueError, E.AssertionError):
    """
    An invalid parameter was specified by the user.
    """

class OutOfBoundsError(E.ValueError):
    """
    The specified item is out of bounds.
    """

class AddressOutOfBoundsError(OutOfBoundsError, E.ArithmeticError):
    """
    The specified address is out of bounds.
    """

class IndexOutOfBoundsError(OutOfBoundsError, E.IndexError, E.KeyError):
    """
    The specified index is out of bounds.
    """

class ItemNotFoundError(ResultMissingError, E.KeyError):
    """
    The specified item or type was not found.
    """

class FunctionNotFoundError(ItemNotFoundError):
    """
    Unable to locate the specified function.
    """

class AddressNotFoundError(ItemNotFoundError):
    """
    Unable to locate the specified address.
    """

class SegmentNotFoundError(ItemNotFoundError):
    """
    Unable to locate the specified segment.
    """

class StructureNotFoundError(ItemNotFoundError):
    """
    Unable to locate the specified structure.
    """

class EnumerationNotFoundError(ItemNotFoundError):
    """
    Unable to locate the specified enumeration.
    """

class MemberNotFoundError(ItemNotFoundError):
    """
    Unable to locate the specified structure or enumeration member.
    """

class RegisterNotFoundError(ItemNotFoundError):
    """
    Unable to locate the specified register.
    """

class ReadOrWriteError(E.IOError, E.ValueError):
    """
    Unable to read or write the specified number of bytes .
    """

class InvalidFormatError(E.KeyError, E.ValueError):
    """
    The specified data has an invalid format.
    """

class SerializationError(E.ValueError, E.IOError):
    """
    There was an error while trying to serialize or deserialize the specified data.
    """

class SizeMismatchError(SerializationError):
    """
    There was an error while trying to serialize or deserialize the specified data due to its size not matching.
    """

class UnknownPrototypeError(E.LookupError):
    """
    The requested prototype does not match any of the ones that are available.
    """

#structure:742 and previous to it should output the module name, classname, and method
#comment:334 should catch whatever tree.find raises
#comment:100 (this needs some kind of error when the symbol or token component is not found)
#interface:283, interface:302, interface:620, interface:640 (this should be a NameError)
