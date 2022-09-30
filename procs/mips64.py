r"""
MIPS series (64-bit) processors (mips64)

This module contains the register state and operand encoders/decoders
for the 64-bit instructions belonging to the MIPS-architecture (MIPS64).
"""

import idaapi, database, processors, __catalog__ as catalog

class MIPS64(processors.mips.MIPS):
    """
    An implementation of all the registers available on the MIPS64 architecture.

    This includes the different coprocessor registers that are also available
    but are treated as special instructions by IDA.

    An instance of this class can be accessed as ``instruction.architecture``
    (or ``instruction.arch``) when the current architecture of the database is MIPS.
    """

    def __init__(self):
        return super(MIPS64, self).__init__(64)

@catalog.processor(idaapi.PLFM_MIPS)
def __newprc__(plfm):
    '''MIPS64'''

    # XXX: If this module hasn't been loaded properly, then this is because IDA hasn't actually started yet.
    if not hasattr(database, 'config'):
        return

    if plfm == idaapi.PLFM_MIPS and database.config.bits() > 32:    # id == 12
        return MIPS64()
    return
