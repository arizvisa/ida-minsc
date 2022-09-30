r"""
Intel 80x86 (64-bit) processor (pc64)

This module contains the register state and operand encoders/decoders
for the 64-bit instruction set (80x86) belonging to Intel's architecture.
The module name directly corresponds to the processor module that is
distributed with the IDA Pro disassembler.
"""

import idaapi, database, processors, __catalog__ as catalog

# This is pretty much a dummy module since we use the exact same
# register state as the 32-bit Intel architecture.
Intel = processors.pc.Intel

@catalog.processor(idaapi.PLFM_386)
def __newprc__(plfm):
    '''Intel architecture 64-bit'''

    # XXX: If this module hasn't been loaded properly, then this is because IDA hasn't actually started yet.
    if not hasattr(database, 'config'):
        return

    if plfm == idaapi.PLFM_386 and database.config.bits() > 32: # id == 15
        return Intel()
    return
