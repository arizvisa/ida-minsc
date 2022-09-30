r"""
ARM (64-bit) processors (arm64)

This module contains the register state and operand encoders/decoders
for the 64-bit extensions (AArch64) of the ARM-architecture family.
"""

import idaapi, database, processors, __catalog__ as catalog

class AArch64(processors.arm.AArch):
    """
    An implementation of all the registers available on the AArch64 (ARM) architecture.

    This is used to locate or manage the different registers that are available.

    An instance of this class can be accessed as ``instruction.architecture``
    (or ``instruction.arch``) when the current architecture of the database is AArch64.
    """

    def __init__(self):
        return super(AArch64, self).__init__(64)

@catalog.processor(idaapi.PLFM_ARM)
def __newprc__(plfm):
    '''AArch64'''

    # XXX: If this module hasn't been loaded properly, then this is because IDA hasn't actually started yet.
    if not hasattr(database, 'config'):
        return

    if plfm == idaapi.PLFM_ARM and database.config.bits() > 32: # id == 1
        return AArch64()
    return
