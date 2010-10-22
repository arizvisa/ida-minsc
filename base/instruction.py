import idc
def get(ea, n):
    '''Returns a tuple describing a specific operand of an instruction'''
    return (idc.GetOpType(ea, n), idc.GetOperandValue(ea, n))

def repr(ea, n):
    '''Returns the repr of an operand of an instruction'''
    return idc.GetOpnd(ea, n)

def mnemonic(ea):
    '''Returns the mnemonic of an instruction'''
    return idc.GetMnem(ea)

def decode(ea):
    import ia32
    '''Disassemble instruction at specified address'''
    def bytegenerator(ea):
        while True:
            yield chr(idc.Byte(ea))
            ea += 1
    return ia32.consume(bytegenerator(ea))
