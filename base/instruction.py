def get(ea, n):
    '''Returns a tuple describing a specific operand of an instruction'''
    return (idc.GetOpType(ea, n), idc.GetOperandValue(ea, n))

def getrepr(ea, n):
    '''Returns the repr of an operand of an instruction'''
    return idc.GetOpnd(ea, n)

def mnemonic(ea):
    '''Returns the mnemonic of an instruction'''
    return idc.GetMnem(ea)
