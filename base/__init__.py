import segment,function,database
import _idaapi as idaapi,ctypes

library = ctypes.WinDLL if __import__('os').name == 'nt' else ctypes.CDLL
class ida:
    lib = library('ida.wll')
    lib.get_true_name.argtypes = [ctypes.c_uint32,ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32]
    lib.get_true_name.restype = ctypes.c_char_p

    @classmethod
    def get_true_name(cls, source, target):
        length = max(idaapi.cvar.inf.namelen, 1024)
        buf = ctypes.c_buffer(length)
        res = cls.lib.get_true_name(source, target, ctypes.byref(buf), len(buf))
        return res
