import idc,idaapi,database
def op_count(ea):
    '''Return the number of operands of given instruction'''
    length = idaapi.decode_insn(ea)
    for c,v in enumerate(idaapi.cmd.Operands):
        if v.type == idaapi.o_void:
            return c
        continue
    # maximum operand ocunt. ida might be wrong here...
    return c

def op(ea, n):
    '''Returns a tuple describing a specific operand of an instruction'''
    return (idc.GetOpType(ea, n), idc.GetOperandValue(ea, n))

def op_repr(ea, n):
    '''Returns the repr of an operand of an instruction'''
    return idc.GetOpnd(ea, n)

def mnemonic(ea):
    '''Returns the mnemonic of an instruction'''
    return idc.GetMnem(ea)

def decode(ea):
    import ia32
    '''Disassemble instruction at specified address using external disassembler'''
    def bytegenerator(ea):
        while True:
            yield chr(idc.Byte(ea))
            ea += 1
    return ia32.consume(bytegenerator(ea))

#import idaapi
#def GetOpType(ea, n):
#    """
#    Get type of instruction operand
#
#    @param ea: linear address of instruction
#    @param n: number of operand:
#        0 - the first operand
#        1 - the second operand
#
#    @return: any of o_* constants or -1 on error
#    """
#    inslen = idaapi.decode_insn(ea)
#    return -1 if inslen == 0 else idaapi.cmd.Operands[n].type

#def GetOperandValue(ea, n):
#    """
#    Get number used in the operand
#
#    This function returns an immediate number used in the operand
#
#    @param ea: linear address of instruction
#    @param n: the operand number
#
#    @return: value
#        operand is an immediate value  => immediate value
#        operand has a displacement     => displacement
#        operand is a direct memory ref => memory address
#        operand is a register          => register number
#        operand is a register phrase   => phrase number
#        otherwise                      => -1
#    """
#    inslen = idaapi.decode_insn(ea)
#    if inslen == 0:
#        return -1
#    op = idaapi.cmd.Operands[n]
#    if not op:
#        return -1
#
#    if op.type in [ idaapi.o_mem, idaapi.o_far, idaapi.o_near, idaapi.o_displ ]:
#        value = op.addr
#    elif op.type == idaapi.o_reg:
#        value = op.reg
#    elif op.type == idaapi.o_imm:
#        value = op.value
#    elif op.type == idaapi.o_phrase:
#        value = op.phrase
#    else:
#        value = -1
#    return value

#def GetOpnd(ea, n):
#    """
#    Get operand of an instruction
#
#    @param ea: linear address of instruction
#    @param n: number of operand:
#        0 - the first operand
#        1 - the second operand
#
#    @return: the current text representation of operand
#    """
#    res = idaapi.ua_outop2(ea, n)
#
#    if not res:
#        return ""
#    else:
#        return idaapi.tag_remove(res)

#o_void     =  idaapi.o_void      #  No Operand                           ----------
#o_reg      =  idaapi.o_reg       #  General Register (al,ax,es,ds...)    reg
#o_mem      =  idaapi.o_mem       #  Direct Memory Reference  (DATA)      addr
#o_phrase   =  idaapi.o_phrase    #  Memory Ref [Base Reg + Index Reg]    phrase
#o_displ    =  idaapi.o_displ     #  Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
#o_imm      =  idaapi.o_imm       #  Immediate Value                      value
#o_far      =  idaapi.o_far       #  Immediate Far Address  (CODE)        addr
#o_near     =  idaapi.o_near      #  Immediate Near Address (CODE)        addr
#o_idpspec0 =  idaapi.o_idpspec0  #  IDP specific type
#o_idpspec1 =  idaapi.o_idpspec1  #  IDP specific type
#o_idpspec2 = idaapi.o_idpspec2  #  IDP specific type
#o_idpspec3 = idaapi.o_idpspec3  #  IDP specific type
#o_idpspec4 = idaapi.o_idpspec4  #  IDP specific type
#o_idpspec5 = idaapi.o_idpspec5  #  IDP specific type
#o_last     = idaapi.o_last      #  first unused type
#
## x86
#o_trreg  =       idaapi.o_idpspec0      # trace register
#o_dbreg  =       idaapi.o_idpspec1      # debug register
#o_crreg  =       idaapi.o_idpspec2      # control register
#o_fpreg  =       idaapi.o_idpspec3      # floating point register
#o_mmxreg  =      idaapi.o_idpspec4      # mmx register
#o_xmmreg  =      idaapi.o_idpspec5      # xmm register
#
## arm
#o_reglist  =     idaapi.o_idpspec1      # Register list (for LDM/STM)
#o_creglist  =    idaapi.o_idpspec2      # Coprocessor register list (for CDP)
#o_creg  =        idaapi.o_idpspec3      # Coprocessor register (for LDC/STC)
#o_fpreg  =       idaapi.o_idpspec4      # Floating point register
#o_fpreglist  =   idaapi.o_idpspec5      # Floating point register list
#o_text  =        (idaapi.o_idpspec5+1)  # Arbitrary text stored in the operand
#
## ppc
#o_spr  =         idaapi.o_idpspec0      # Special purpose register
#o_twofpr  =      idaapi.o_idpspec1      # Two FPRs
#o_shmbme  =      idaapi.o_idpspec2      # SH & MB & ME
#o_crf  =         idaapi.o_idpspec3      # crfield      x.reg
#o_crb  =         idaapi.o_idpspec4      # crbit        x.reg
#o_dcr  =         idaapi.o_idpspec5      # Device control register
#

def isGlobalRef(ea):
    '''Return True if the specified instruction references data (like a global)'''
    return len(database.dxdown(ea)) > len(database.cxdown(ea))

def isImportRef(ea):
    return len(database.dxdown(ea)) == len(database.cxdown(ea)) and len(database.cxdown(ea)) > 0

