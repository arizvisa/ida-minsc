try:
    import idc,comment
    class ida(object):
        def __init__(self):
            assert False, 'This object is not intended to be instantiated'

        @classmethod
        def __color_write(cls, ea, rgb, what=1):
            if rgb is None:
                return idc.SetColor(ea, what, 0xffffffff)

            a = rgb & 0xff000000
            rgb &= 0x00ffffff

            bgr = 0
            for i in xrange(3):
                bgr,rgb = ((bgr*0x100) + (rgb&0xff), rgb/0x100)
            return idc.SetColor(ea, what, bgr)

        @classmethod
        def __color_read(cls, ea, what=1):
            bgr = idc.GetColor(ea, what)
            if bgr == 0xffffffff:
                return None

            a = bgr&0xff000000
            bgr &= 0x00ffffff

            rgb = 0
            for i in xrange(3):
                rgb,bgr = ((rgb*0x100) + (bgr&0xff), bgr/0x100)
            return rgb

        @classmethod
        def color(cls, ea, *args, **kwds):
            '''color(address, rgb?) -> fetches or stores a color to the specified address'''
            if len(args) == 0:
                return cls.__color_read(ea, *args, **kwds)
            return cls.__color_write(ea, *args, **kwds)

        @classmethod
        def db_read(cls, address, key=None, repeatable=0):
            res = idc.GetCommentEx(address, repeatable)
            dict = comment.toDict(res)

            name = idc.NameEx(address, address)
            if name:
                dict['__name__'] = name

            c = cls.color(address)
            if c is not None:
                dict['__color__'] = c

            if '__address__' not in dict:
                dict['__address__'] = address

            if key is not None:
                return dict[key]
            return dict

        @classmethod
        def db_write(cls, address, key, value, repeatable=0):
            dict = cls.db_read(address, repeatable=repeatable)
            dict[key] = value

            if '__color__' in dict:
                value = dict['__color__']
                cls.color(address, value)
                del(dict['__color__'])

            if '__address__' in dict:
                del(dict['__address__'])

            res = comment.toString(dict)
            if repeatable:
                return idc.MakeRptCmt(address, res)

            return idc.MakeComm(address, res)

        @classmethod
        def db_tag(cls, address, *args, **kwds):
            '''tag(address, key?, value?, repeatable=True/False) -> fetches/stores a tag from specified address'''

            if idc.GetFunctionAttr(address, idc.FUNCATTR_FLAGS) != idc.BADADDR:
                if 'repeatable' not in kwds:
                    kwds['repeatable'] = False
            else:
                # not in a function, could be a global, so it's now repeatable
                if 'repeatable' not in kwds:
                    kwds['repeatable'] = True
                pass

            if len(args) < 2:
                return cls.db_read(int(address), *args, **kwds)

            key,value = args
            return cls.db_write(int(address), key, value, **kwds)

        @classmethod
        def fn_read(cls, address, key=None, repeatable=1):
            address = idc.GetFunctionAttr(address, idc.FUNCATTR_START)
            if address == idc.BADADDR:
                raise ValueError("Address %x not in function"% address)

            res = idc.GetFunctionCmt(int(address), repeatable)
            dict = comment.toDict(res)
            if '__name__' not in dict:
                dict['__name__'] = idc.GetFunctionName(address)

            if '__address__' not in dict:
                dict['__address__'] = address

            if key is not None:
                return dict[key]
            return dict

        @classmethod
        def fn_write(cls, address, key, value, repeatable=1):
            dict = cls.fn_read(address, repeatable=repeatable)
            dict[key] = value
            if '__address__' in dict:
                del(dict['__address__'])
            res = comment.toString(dict)
            return idc.SetFunctionCmt(int(address), res, repeatable)

        @classmethod
        def fn_tag(cls, address, *args, **kwds):
            '''tag(address, key?, value?, repeatable=True/False) -> fetches/stores a tag from a function's comment'''
            if len(args) < 2:
                return cls.fn_read(address, *args, **kwds)
            key,value = args
            return cls.fn_write(address, key, value, **kwds)

except ImportError:
    pass
