"""
Xtensa lifting to BNIL

Here we provide a `lift` function that takes a decoded instruction and an
address where that instruction is, and we return BNIL.
"""
from binaryninja import Architecture, LowLevelILLabel, LLIL_TEMP

from .instruction import Instruction, sign_extend

def _reg_name(insn, fmt, offset=0):
    """Get the concrete register for a particular part of an instruction

    For example, if the docs say an instruction writes to "as", we call this
    function, which will check the `s` decoded control signal (say it's "7") and
    return "a7" for passing to BNIL.
    """
    if fmt.startswith("a"):
        rest = fmt[1:]
        val = getattr(insn, rest, None)
        if val is None:
            raise Exception("Could not find property " + fmt)
        return "a" + str(val+offset)
    elif fmt.startswith("b"):
        rest = fmt[1:]
        val = getattr(insn, rest, None)
        if val is None:
            raise Exception("Could not find property " + fmt)
        return int(val+offset)          
    elif fmt.startswith("f"):
        rest = fmt[1:]
        val = getattr(insn, rest, None)
        if val is None:
            raise Exception("Could not find property " + fmt)
        return "f" + str(val+offset)
    elif fmt.startswith("epc"):
        rest = fmt[3:]
        val = getattr(insn, rest, None)
        if val is None:
            raise Exception("Could not find property " + fmt)
        return "epc" + str(val+offset)
    else:
        raise Exception("Unimplemented reg name fmt: " + fmt)

def lift(insn, addr, il, data=None):
    """Dispatch function for lifting

    Looks up _lift_MNEM() in the current global namespace (I think that's just
    the module level?) and calls it if it exists, otherwise we say the
    instruction is unimplemented.
    """
    try:
        # We replace the "." in mnemonics with a "_", as we do in several other 
        # places in the code.
        # At some point, this should become a property of the Instruction.
        func = globals()["_lift_" + insn.mnem.replace(".", "_")]
    except KeyError:
        il.append(il.unimplemented())
        return insn.length

    if "LOOP" in insn.mnem:
        return func(insn, addr, il, data)

    return func(insn, addr, il)

# Helpers for some shared code between instructions

def _lift_cond(cond, insn, addr, il):
    """Helper for lifting conditional jumps
    
    We pass in an IL condition (LowLevelILExpr) and this function lifts a IL
    conditional that will jump to `insn.target_offset(addr)` if the condition is
    true, otherwise we continue to the next instruction.
    """
    true_label = il.get_label_for_address(Architecture['xtensa'],
                                           insn.target_offset(addr))
    false_label = il.get_label_for_address(Architecture['xtensa'],
                                          addr + insn.length)
    must_mark_true = False
    if true_label is None:
        true_label = LowLevelILLabel()
        must_mark_true = True

    must_mark_false = False
    if false_label is None:
        false_label = LowLevelILLabel()
        must_mark_false = True

    il.append(
        il.if_expr(cond,
                   true_label,
                   false_label
                   ))
    if must_mark_true:
        il.mark_label(true_label)
        il.append(il.jump(il.const(4, insn.target_offset(addr))))
    if must_mark_false:
        il.mark_label(false_label)
        il.append(il.jump(il.const(4, addr + insn.length)))
    return insn.length

def _lift_cmov(cond, insn, addr, il, float=False):
    """Helper for lifting conditional moves
    
    We pass in an IL condition (LowLevelILExpr) and this function lifts a move
    from as to ar if the condition is true. In either case we then continue with
    the next instruction after the (potential) move.
    """
    true_label = LowLevelILLabel()
    false_label = LowLevelILLabel()
    il.append(il.if_expr(cond, true_label, false_label))
    il.mark_label(true_label)
    if float:
        il.append(il.set_reg(4, _reg_name(insn, "fr"), il.reg(4, _reg_name(insn, "fs"))))
    else:
        il.append(il.set_reg(4, _reg_name(insn, "ar"), il.reg(4, _reg_name(insn, "as"))))
    il.mark_label(false_label)
    return insn.length

# Instructions are grouped based on the Xtensa options in which they appear.

##############################################
####### Core Architecture Instrucitons #######
############# Code Density Option ############
##############################################

def _lift_ABS(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.float_abs(4, il.reg(4, _reg_name(insn, "at"))
                                )))
    return insn.length

def _lift_ADD(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.add(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.reg(4, _reg_name(insn, "at"))
                          )))
    return insn.length

def _lift_ADD_N(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.add(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.reg(4, _reg_name(insn, "at"))
                          )))
    return insn.length
    
def _lift_ADDI(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.add(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.const(4, insn.simm8())
                          )))
    return insn.length
def _lift_ADDI_N(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.add(4,
                       il.reg(4, _reg_name(insn, "as")),
                       il.const(4, insn.inline0(addr))
                   )))
    return insn.length

def _lift_ADDMI(insn, addr, il):
    constant = sign_extend(insn.imm8, 8) << 8
    il.append(
        il.set_reg(4, _reg_name(insn, "at"),
                   il.add(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.const(4, constant))))
    return insn.length


def _lift_addx(x_bits, insn, addr, il):
    """Helper for ADDX2, ADDX4, ADDX8"""
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.add(4,
                          il.shift_left(4,
                                        il.reg(4, _reg_name(insn, "as")),
                                        il.const(4, x_bits)),
                          il.reg(4, _reg_name(insn, "at")))))
    return insn.length


def _lift_ADDX2(insn, addr, il):
    return _lift_addx(1, insn, addr, il)

def _lift_ADDX4(insn, addr, il):
    return _lift_addx(2, insn, addr, il)

def _lift_ADDX8(insn, addr, il):
    return _lift_addx(3, insn, addr, il)

def _lift_AND(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.and_expr(4,
                              il.reg(4, _reg_name(insn, "as")),
                              il.reg(4, _reg_name(insn, "at"))
                              )))
    return insn.length

def _lift_BALL(insn, addr, il):
    cond = il.compare_equal(4,
                            il.and_expr(4,
                                il.reg(4, _reg_name(insn, "at")),
                                il.not_expr(4, il.reg(4, _reg_name(insn, "as")))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BANY(insn, addr, il):
    cond = il.compare_not_equal(4,
                            il.and_expr(4,
                                il.reg(4, _reg_name(insn, "as")),
                                il.reg(4, _reg_name(insn, "at"))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BBC(insn, addr, il):
    cond = il.compare_equal(4,
                            il.test_bit(4,
                                il.reg(4, _reg_name(insn, "as")),
                                # Strictly speaking we're supposed to check the
                                # low 5 bits of at. I don't really see the need
                                # to clutter the UI with it

                                # Also: TODO: figure out which way Binja numbers
                                # the bits
                                il.reg(4, _reg_name(insn, "at"))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BBCI(insn, addr, il):
    cond = il.compare_equal(4,
                            il.test_bit(4,
                                il.reg(4, _reg_name(insn, "as")),
                                # Also: TODO: figure out which way Binja numbers
                                # the bits
                                il.const(4, insn.inline0(addr))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)
_lift_BBCI_L = _lift_BBCI # We use Little Endinan --> BBCI and BBCI_L are the same

def _lift_BBS(insn, addr, il):
    cond = il.test_bit(4,
        il.reg(4, _reg_name(insn, "as")),
        # Strictly speaking we're supposed to check the
        # low 5 bits of at. I don't really see the need
        # to clutter the UI with it
        il.reg(4, _reg_name(insn, "at")))
    return _lift_cond(cond, insn, addr, il)


def _lift_BBSI(insn, addr, il):
    cond = il.test_bit(4,
        il.reg(4, _reg_name(insn, "as")),
        il.const(4, insn.inline0(addr)))
    return _lift_cond(cond, insn, addr, il)
_lift_BBSI_L = _lift_BBSI # We use Little Endinan --> BBSI and BBSI_L are the same


def _lift_BEQ(insn, addr, il):
    cond = il.compare_equal(4,
                            il.reg(4, _reg_name(insn, "as")),
                            il.reg(4, _reg_name(insn, "at")))
    return _lift_cond(cond, insn, addr, il)

def _lift_BEQI(insn, addr, il):
    cond = il.compare_equal(4, il.reg(4, _reg_name(insn, "as")), il.const(4, insn.b4const()))
    return _lift_cond(cond, insn, addr, il)

def _lift_BEQZ(insn, addr, il):
    cond = il.compare_equal(4, il.reg(4, _reg_name(insn, "as")), il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

_lift_BEQZ_N = _lift_BEQZ

def _lift_BGE(insn, addr, il):
    cond = il.compare_signed_greater_equal(4,
                                           il.reg(4, _reg_name(insn, "as")),
                                           il.reg(4, _reg_name(insn, "at"))
                                           )
    return _lift_cond(cond, insn, addr, il)

def _lift_BGEI(insn, addr, il):
    cond = il.compare_signed_greater_equal(4,
                                           il.reg(4, _reg_name(insn, "as")),
                                           il.const(4, insn.b4const())
                                           )
    return _lift_cond(cond, insn, addr, il)

def _lift_BGEU(insn, addr, il):
    cond = il.compare_unsigned_greater_equal(4,
                                             il.reg(4, _reg_name(insn, "as")),
                                             il.reg(4, _reg_name(insn, "at"))
    )
    return _lift_cond(cond, insn, addr, il)

def _lift_BGEUI(insn, addr, il):
    cond = il.compare_unsigned_greater_equal(4,
                                           il.reg(4, _reg_name(insn, "as")),
                                           il.const(4, insn.b4constu())
                                           )
    return _lift_cond(cond, insn, addr, il)

def _lift_BGEZ(insn, addr, il):
    cond = il.compare_signed_greater_equal(4,
                                           il.reg(4, _reg_name(insn, "as")),
                                           il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BLT(insn, addr, il):
    cond = il.compare_signed_less_than(4,
                                       il.reg(4, _reg_name(insn, "as")),
                                       il.reg(4, _reg_name(insn, "at"))
                                       )
    return _lift_cond(cond, insn, addr, il)

def _lift_BLTI(insn, addr, il):
    cond = il.compare_signed_less_than(4,
                                       il.reg(4, _reg_name(insn, "as")),
                                       il.const(4, insn.b4const())
                                       )
    return _lift_cond(cond, insn, addr, il)

def _lift_BLTU(insn, addr, il):
    cond = il.compare_unsigned_less_than(4,
                                         il.reg(4, _reg_name(insn, "as")),
                                         il.reg(4, _reg_name(insn, "at"))
                                         )
    return _lift_cond(cond, insn, addr, il)

def _lift_BLTUI(insn, addr, il):
    cond = il.compare_unsigned_less_than(4,
                                         il.reg(4, _reg_name(insn, "as")),
                                         il.const(4, insn.b4constu())
                                       )
    return _lift_cond(cond, insn, addr, il)

def _lift_BLTZ(insn, addr, il):
    cond = il.compare_signed_less_than(4,
                                       il.reg(4, _reg_name(insn, "as")),
                                       il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)


def _lift_BNALL(insn, addr, il):
    cond = il.compare_not_equal(4,
                            il.and_expr(4,
                                il.reg(4, _reg_name(insn, "at")),
                                il.not_expr(4, il.reg(4, _reg_name(insn, "as")))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_BNE(insn, addr, il):
    cond = il.compare_not_equal(4,
                            il.reg(4, _reg_name(insn, "as")),
                            il.reg(4, _reg_name(insn, "at")))
    return _lift_cond(cond, insn, addr, il)

def _lift_BNEI(insn, addr, il):
    cond = il.compare_not_equal(4,
                                il.reg(4, _reg_name(insn, "as")),
                                il.const(4, insn.b4const()))
    return _lift_cond(cond, insn, addr, il)

def _lift_BNEZ(insn, addr, il):
    cond = il.compare_not_equal(4,
                                il.reg(4, _reg_name(insn, "as")),
                                il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

_lift_BNEZ_N = _lift_BNEZ

def _lift_BNONE(insn, addr, il):
    cond = il.compare_equal(4,
                            il.and_expr(4,
                                il.reg(4, _reg_name(insn, "as")),
                                il.reg(4, _reg_name(insn, "at"))
                            ),
                            il.const(4, 0))
    return _lift_cond(cond, insn, addr, il)

def _lift_DSYNC(insn, addr, il):
    il.append(il.intrinsic([], "dsync", []))
    return insn.length

def _lift_ESYNC(insn, addr, il):
    il.append(il.intrinsic([], "esync", []))
    return insn.length

def _lift_ISYNC(insn, addr, il):
    il.append(il.intrinsic([], "isync", []))
    return insn.length
def _lift_RSYNC(insn, addr, il):
    il.append(il.intrinsic([], "rsync", []))
    return insn.length

def _lift_EXTUI(insn, addr, il):
    inp = il.reg(4, _reg_name(insn, "at"))

    mask = (2 ** insn.inline1(addr)) - 1
    mask_il = il.const(4, mask)

    shiftimm = insn.extui_shiftimm()
    if shiftimm:
        shift_il = il.const(1, shiftimm)
        shifted = il.logical_shift_right(4, inp, shift_il)
        anded = il.and_expr(4, shifted, mask_il)
    else:
        # If we don't have to shift (thus shiftimm should be 0), then don't emit
        # the IL for it
        anded = il.and_expr(4, inp, mask_il)

    il.append(il.set_reg(4, _reg_name(insn, "ar"), anded))
    return insn.length

def _lift_EXTW(insn, addr, il):
    il.append(il.intrinsic([], "extw", []))
    return insn.length

def _lift_J(insn, addr, il):
    il.append(il.jump(il.const(4, insn.target_offset(addr))))
    return insn.length

def _lift_JX(insn, addr, il):
    il.append(il.jump(il.reg(4, _reg_name(insn, "as"))))
    return insn.length

def _lift_MEMW(insn, addr, il):
    il.append(il.intrinsic([], "memw", []))
    return insn.length

def _lift_MOV_N(insn, addr, il):
    il.append( il.set_reg(4, _reg_name(insn, "at"),
                              il.reg(4, _reg_name(insn, "as"))))
    return insn.length

def _lift_MOVEQZ(insn, addr, il):
    cond = il.compare_equal(4,
                            il.reg(4, _reg_name(insn, "at")),
                            il.const(4, 0))
    return _lift_cmov(cond, insn, addr, il)

def _lift_MOVGEZ(insn, addr, il):
    cond = il.compare_signed_greater_equal(4,
                            il.reg(4, _reg_name(insn, "at")),
                            il.const(4, 0))
    return _lift_cmov(cond, insn, addr, il)

def _lift_MOVNEZ(insn, addr, il):
    cond = il.compare_not_equal(4,
                            il.reg(4, _reg_name(insn, "at")),
                            il.const(4, 0))
    return _lift_cmov(cond, insn, addr, il)

def _lift_MOVLTZ(insn, addr, il):
    cond = il.compare_signed_less_than(4,
                            il.reg(4, _reg_name(insn, "at")),
                            il.const(4, 0))
    return _lift_cmov(cond, insn, addr, il)

def _lift_MOVI(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                         il.const(4, insn.inline0(addr))))
    return insn.length

def _lift_MOVI_N(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "as"),
                   il.const(4, insn.inline0(addr))
                   ))
    return insn.length

def _lift_NEG(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.neg_expr(4, il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_NOP(insn, addr, il):
    il.append(il.nop())
    return insn.length
_lift_NOP_N = _lift_NOP

def _lift_OR(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.or_expr(4,
                              il.reg(4, _reg_name(insn, "as")),
                              il.reg(4, _reg_name(insn, "at"))
                              )))
    return insn.length

def _lift_SLL(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.shift_left(4,
                                       il.reg(4, _reg_name(insn, "as")),
                                       il.reg(1, "sar"))))
    return insn.length

def _lift_SLLI(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                   il.shift_left(4,
                       il.reg(4, _reg_name(insn, "as")),
                       il.const(1, insn.inline0(addr)))))
    return insn.length

def _lift_SRA(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.arith_shift_right(4,
                                              il.reg(4, _reg_name(insn, "at")),
                                              il.reg(1, "sar"))))
    return insn.length

def _lift_SRAI(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.arith_shift_right(4,
                                        il.reg(4, _reg_name(insn, "at")),
                                        il.const(4, insn.inline0(addr)))))
    return insn.length

def _lift_SRC(insn, addr, il):
    operand = il.reg_split(8,
                           _reg_name(insn, "as"),
                           _reg_name(insn, "at"))
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.low_part(4, il.logical_shift_right(8, operand,
                                                                 il.reg(1, "sar")))))
    return insn.length

def _lift_SRL(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
                         il.logical_shift_right(4,
                                                il.reg(4, _reg_name(insn, "at")),
                                                il.reg(1, "sar"))))
    return insn.length

def _lift_SRLI(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.logical_shift_right(4,
                                          il.reg(4, _reg_name(insn, "at")),
                                          il.const(4, insn.s))))
    return insn.length

def _lift_SSA8L(insn, addr, il):
    # Get last 2 bits of as
    low_part = il.and_expr(1,
        il.low_part(1, il.reg(4, _reg_name(insn, "as"))),
        il.const(1,3)
    ) 
    result = il.shift_left(1, low_part, il.const(1, 3))
    il.append(il.set_reg(1, "sar", result))
    return insn.length

def _lift_SSA8B(insn, addr, il):
    low_part = il.and_expr(1,
        il.low_part(1, il.reg(4, _reg_name(insn, "as"))),
        il.const(1,3)
    ) 
    result = il.sub(1, il.const(1, 32), il.shift_left(1, low_part, il.const(1, 3)))
    il.append(il.set_reg(1, "sar", result))
    return insn.length

def _lift_SSAI(insn, addr, il):
    il.append(il.set_reg(1, "sar", 
                         il.const(1, insn.inline0(addr))))
    return insn.length

def _lift_SSL(insn, addr, il):
    il.append(il.set_reg(1, "sar",
                         il.sub(1,
                                il.const(1, 32),
                                il.low_part(1, il.reg(4, _reg_name(insn, "as")))
                                )))
    return insn.length

def _lift_SSR(insn, addr, il):
    il.append(il.set_reg(1, "sar",
                         il.low_part(1, il.reg(4, _reg_name(insn, "as")))))
    return insn.length

def _lift_SUB(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.sub(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.reg(4, _reg_name(insn, "at"))
                          )))
    return insn.length

def _lift_subx(x_bits, insn, addr, il):
    """Helper for SUBX2, SUBX4, SUBX8"""
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.sub(4,
                          il.shift_left(4,
                                        il.reg(4, _reg_name(insn, "as")),
                                        il.const(4, x_bits)),
                          il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_SUBX2(insn, addr, il):
    return _lift_subx(1, insn, addr, il)

def _lift_SUBX4(insn, addr, il):
    return _lift_subx(2, insn, addr, il)

def _lift_SUBX8(insn, addr, il):
    return _lift_subx(3, insn, addr, il)

def _lift_XOR(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.xor_expr(4,
                          il.reg(4, _reg_name(insn, "as")),
                          il.reg(4, _reg_name(insn, "at"))
                          )))
    return insn.length

##################################################
# Load and Store instructions in Core Architecture:

def _lift_L8UI(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.imm8))
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                   il.zero_extend(4,
                                  il.load(1, va))))
    return insn.length

def _lift_L16SI(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                         il.sign_extend(4, il.load(2, va))))
    return insn.length

def _lift_L16UI(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                         il.zero_extend(4, il.load(2, va))))
    return insn.length


def _lift_L32I(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                         il.load(4, va)))
    return insn.length

def _lift_L32I_N(insn, addr, il):
    _as = il.reg(4, _reg_name(insn, "as"))
    imm = il.const(4, insn.inline0(addr))
    va = il.add(4, _as, imm)
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                   il.load(4, va)))
    return insn.length

def _lift_L32R(insn, addr, il):
    va = il.const(4, insn.mem_offset(addr))
    il.append(il.set_reg(4, _reg_name(insn, "at"),
                   il.load(4, va)))
    return insn.length

# Store instructions
def _lift_S8I(insn, addr, il):
    il.append(il.store(1, il.add(4,
                                 il.reg(4, _reg_name(insn, "as")),
                                 il.const(4, insn.imm8)),
                       il.low_part(1, il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_S16I(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr))
                )
    il.append(il.store(2, va,
                 il.low_part(2, il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_S32I(insn, addr, il):
    va = il.add(4,
                il.reg(4, _reg_name(insn, "as")),
                il.const(4, insn.inline0(addr)))
    il.append(
        il.store(4, va, il.reg(4, _reg_name(insn, "at"))))
    return insn.length

def _lift_S32I_N(insn, addr, il):
    _as = il.reg(4, _reg_name(insn, "as"))
    imm = il.const(4, insn.inline0(addr))
    va = il.add(4, _as, imm)
    il.append(
        il.store(4, va, il.reg(4, "a" + str(insn.t))))
    return insn.length

##############################################
# Special register instructions: RSR, WSR, XSR

def _lift_RSR(insn, addr, il):
    sr = insn._special_reg_map.get(insn.sr)
    if not sr:
        il.append(il.unimplemented())
    else:
        il.append( il.set_reg(4, _reg_name(insn, "at"),  il.reg(4, sr[0].lower())))

    return insn.length

def _lift_WSR(insn, addr, il):
    sr = insn._special_reg_map.get(insn.sr)
    if not sr:
        il.append(il.unimplemented())
    else:
        il.append( il.set_reg(4, sr[0].lower(),  il.reg(4, _reg_name(insn, "at"))))
    return insn.length

def _lift_XSR(insn, addr, il):
    sr = insn._special_reg_map.get(insn.sr)
    if not sr:
        il.append(il.unimplemented())
    else:
        temp = LLIL_TEMP(0)
        sr_reg = sr[0].lower()
        at_reg = _reg_name(insn, "at")

        il.append(il.set_reg(4, temp, il.reg(4, sr_reg)))
        il.append(il.set_reg(4, sr_reg, il.reg(4, at_reg)))
        il.append(il.set_reg(4, at_reg, il.reg(4, temp)))
    return insn.length

##############################################
# User register instructions: WUR, RUR

def _lift_RUR(insn, addr, il):
    sr = insn._user_reg_map.get(insn.sr)
    if not sr:
        il.append(il.unimplemented())
    else:
        il.append( il.set_reg(4, _reg_name(insn, "at"),  il.reg(4, sr[0].lower())))

    return insn.length

def _lift_WUR(insn, addr, il):
    sr = insn._user_reg_map.get(insn.sr)
    if not sr:
        il.append(il.unimplemented())
    else:
        il.append( il.set_reg(4, sr[0].lower(),  il.reg(4, _reg_name(insn, "at"))))
    return insn.length

# TODO: RER
# TODO: WER

###############################################
### Core Architecture calling instructions ####
########## Windowed Register Option ###########
###############################################

def _lift_CALL0(insn, addr, il):
    dest = il.const(4, insn.target_offset(addr))
    il.append(
        il.call(dest))
    return insn.length

def _lift_CALLX0(insn, addr, il):
    dest = il.reg(4, _reg_name(insn, "as"))
    il.append(
        il.call(dest))
    return insn.length

def _lift_CALLXn(insn, addr, il, n):
    dest = il.reg(4, _reg_name(insn, "as"))
    for i in range(n): il.append(il.set_reg(4, LLIL_TEMP(i), il.reg(4, 'a' + str(i))))
    for i in range(16-n): il.append(il.set_reg(4, 'a' + str(i), il.reg(4, 'a' + str(i+n))))
    il.append(il.call(dest))
    for i in range(16-n): il.append(il.set_reg(4, 'a' + str(i+n), il.reg(4, 'a' + str(i))))
    for i in range(n): il.append(il.set_reg(4, 'a' + str(i), il.reg(4, LLIL_TEMP(i))))


    return insn.length
_lift_CALLX4  = lambda insn, addr,il: _lift_CALLXn(insn, addr, il, 4)
_lift_CALLX8  = lambda insn, addr,il: _lift_CALLXn(insn, addr, il, 8)
_lift_CALLX12 = lambda insn, addr,il: _lift_CALLXn(insn, addr, il, 12)


def _lift_CALLn(insn, addr, il, n):
    dest = il.const(4, insn.target_offset(addr))
    for i in range(n): il.append(il.set_reg(4, LLIL_TEMP(i), il.reg(4, 'a' + str(i))))
    for i in range(16-n): il.append(il.set_reg(4, 'a' + str(i), il.reg(4, 'a' + str(i+n))))
    il.append(il.call(dest))
    for i in range(16-n): il.append(il.set_reg(4, 'a' + str(i+n), il.reg(4, 'a' + str(i))))
    for i in range(n): il.append(il.set_reg(4, 'a' + str(i), il.reg(4, LLIL_TEMP(i))))

    return insn.length
_lift_CALL4  = lambda insn, addr,il: _lift_CALLn(insn, addr, il, 4)
_lift_CALL8  = lambda insn, addr,il: _lift_CALLn(insn, addr, il, 8)
_lift_CALL12 = lambda insn, addr,il: _lift_CALLn(insn, addr, il, 12)



def _lift_RET(insn, addr, il):
    dest = il.reg(4, 'a0')
    il.append(il.ret(dest))
    return insn.length
_lift_RET_N = _lift_RET

# Dummy lifting to allow the lifter and disassemble to find the right building blocks.
_lift_RETW = _lift_RET
_lift_RETW_N = _lift_RET
_lift_ENTRY = _lift_NOP

def _lift_RFWO(insn, addr, il):
    dest = il.reg(4, 'epc1')
    il.append(il.ret(dest))
    return insn.length
_lift_RFWU = _lift_RFWO

# MOVSP behaves the same as MOV.N, because we do not keep track of 
# WindowStart when implementing windowed registers
# Because of this, we also don't need to implement ROTW
# We also do not implement the load and store used specifically for window exceptions
_lift_MOVSP = _lift_MOV_N

# TODO: def _lift_ROTW
# TODO: def _lift_S32E
# TODO: def _lift_L32E

##############################################
####### 16-bit Integer Multiply Option #######
##############################################

def _lift_MUL16S(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.mult(4,
                           il.sign_extend(4,
                               il.low_part(2,
                                           il.reg(4, _reg_name(insn, "as")))),
                           il.sign_extend(4,
                               il.low_part(2,
                                           il.reg(4, _reg_name(insn, "at"))))
                           )))
    return insn.length

def _lift_MUL16U(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.mult(4,
                           il.zero_extend(4,
                               il.low_part(2,
                                           il.reg(4, _reg_name(insn, "as")))),
                           il.zero_extend(4,
                               il.low_part(2,
                                           il.reg(4, _reg_name(insn, "at"))))
                           )))
    return insn.length

##############################################
####### 32-bit Integer Multiply Option #######
##############################################

def _lift_MULL(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
                   il.mult(4,
                           il.reg(4, _reg_name(insn, "as")),
                           il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_MULSH(insn, addr, il):
    temp = il.mult_double_prec_signed(4, 
                                      il.reg(4, _reg_name(insn, "as")), 
                                      il.reg(4, _reg_name(insn, "as")))
    # Get the most significant 32 bits by shifting to the right
    result = il.logical_shift_right(4, temp, il.const(1, 32))
    il.append(il.set_reg(4, _reg_name(insn, "ar"), result))
    return insn.length
def _lift_MULUH(insn, addr, il):
    temp = il.mult_double_prec_unsigned(4, 
                                        il.reg(4, _reg_name(insn, "as")), 
                                        il.reg(4, _reg_name(insn, "as")))
    # Get the most significant 32 bits by shifting to the right
    result = il.logical_shift_right(4, temp, il.const(1, 32))
    il.append(il.set_reg(4, _reg_name(insn, "ar"), result))
    return insn.length

###############################################
######### 32-bit Integer Divide Option ########
###############################################

def _lift_REMU(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
        il.mod_unsigned(4,
                il.reg(4, _reg_name(insn, "as")),
                il.reg(4, _reg_name(insn, "at")))))

    return insn.length
def _lift_REMS(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
        il.mod_signed(4,
                il.reg(4, _reg_name(insn, "as")),
                il.reg(4, _reg_name(insn, "at")))))
    return insn.length

def _lift_QUOU(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
        il.div_unsigned(4,
                il.reg(4, _reg_name(insn, "as")),
                il.reg(4, _reg_name(insn, "at")))))

    return insn.length
def _lift_QUOS(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"),
        il.div_signed(4,
                il.reg(4, _reg_name(insn, "as")),
                il.reg(4, _reg_name(insn, "at")))))
    return insn.length


#####################################
# Floating-point Coprocessor Option #
#####################################

# Binary/unary arithmetic operations

def _lift_ABS_S(insn, addr, il):
    il.append(
        il.set_reg(4, _reg_name(insn, "fr"),
                   il.float_abs(4, il.reg(4, _reg_name(insn, "ft")) # Note: No flag parameter
                                )))
    return insn.length
def _lift_ADD_S(insn, addr, il): 
    il.append(
        il.set_reg(4, _reg_name(insn, "fr"),
                   il.float_add(4,  # Note: No flag parameter
                          il.reg(4, _reg_name(insn, "fs")),
                          il.reg(4, _reg_name(insn, "ft"))
                          )))
    return insn.length
def _lift_MUL_S(insn, addr, il): 
    il.append(
        il.set_reg(4, _reg_name(insn, "fr"),
            il.float_mult(4,    
                il.reg(4, _reg_name(insn, "fs")),
                il.reg(4, _reg_name(insn, "ft"))
            )))
    return insn.length
def _lift_NEG_S(insn, addr, il): 
    il.append(
        il.set_reg(4, _reg_name(insn, "fr"),
            il.float_neg(4, il.reg(4, _reg_name(insn, "fs")))
            ))
    return insn.length
def _lift_SUB_S(insn, addr, il): 
    il.append(
        il.set_reg(4, _reg_name(insn, "fr"),
            il.float_sub(4,    
                il.reg(4, _reg_name(insn, "fs")),
                il.reg(4, _reg_name(insn, "ft"))
            )))
    return insn.length
def _lift_MADD_S(insn, addr, il): 
    il.append(
        il.set_reg(4, _reg_name(insn, "fr"),
            il.float_add(4,
                il.reg(4, _reg_name(insn, "fr")),
                il.float_mult(4,    
                    il.reg(4, _reg_name(insn, "fs")),
                    il.reg(4, _reg_name(insn, "ft"))
                ))))
    return insn.length
def _lift_MSUB_S(insn, addr, il): 
    il.append(
        il.set_reg(4, _reg_name(insn, "fr"),
            il.float_sub(4,
                il.reg(4, _reg_name(insn, "fr")),
                il.float_mult(4,    
                    il.reg(4, _reg_name(insn, "fs")),
                    il.reg(4, _reg_name(insn, "ft"))
                ))))
    return insn.length
    
# Float to Int Rounding functions
def _lift_CEIL_S(insn, addr, il): 
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
            il.ceil(4,  # Note: No flag parameter
                il.float_mult(4,    il.reg(4, _reg_name(insn, "fs")),
                                    il.float_const_single(2**insn.t)))))
    return insn.length
def _lift_FLOAT_S(insn, addr, il): 
    il.append(
        il.set_reg(4, _reg_name(insn, "fr"),
            il.float_mult(4,    il.int_to_float(4, il.reg(4, _reg_name(insn, "as"))),
                                il.float_const_single(2.0**(-insn.t)))))
    return insn.length
_lift_UFLOAT_S = _lift_FLOAT_S
def _lift_FLOOR_S(insn, addr, il): 
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
            il.floor(4,         # Note: No flag parameter
                il.float_mult(4,    il.reg(4, _reg_name(insn, "fs")),
                                    il.float_const_single(2.0**insn.t)))))
    return insn.length
def _lift_TRUNC_S(insn, addr, il): 
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
            il.float_trunc(4,   # Note: No flag parameter
                il.float_mult(4,    il.reg(4, _reg_name(insn, "fs")),
                                    il.float_const_single(2**insn.t)))))
    return insn.length
_lift_UTRUNC_S = _lift_TRUNC_S
def _lift_ROUND_S(insn, addr, il): 
    il.append(
        il.set_reg(4, _reg_name(insn, "ar"),
            il.round_to_int(4,   # Note: No flag parameter
                il.float_mult(4,    il.reg(4, _reg_name(insn, "fs")),
                                    il.float_const_single(2**insn.t)))))
    return insn.length

# Move operations
def _lift_MOV_COND_S(insn, addr, il, comp):
    cond = comp(4, il.reg(4, _reg_name(insn, "at")), il.const(4, 0))
    return _lift_cmov(cond, insn, addr, il, True)
_lift_MOVEQZ_S = lambda insn, addr, il: _lift_MOV_COND_S(insn, addr, il, il.compare_equal)
_lift_MOVNEZ_S = lambda insn, addr, il: _lift_MOV_COND_S(insn, addr, il, il.compare_not_equal)
_lift_MOVGEZ_S = lambda insn, addr, il: _lift_MOV_COND_S(insn, addr, il, il.compare_signed_greater_equal)
_lift_MOVLTZ_S = lambda insn, addr, il: _lift_MOV_COND_S(insn, addr, il, il.compare_signed_less_than)
_lift_MOVF_S = lambda insn, addr, il: _lift_MOVFT(insn, addr, il, 0, True)
_lift_MOVT_S = lambda insn, addr, il: _lift_MOVFT(insn, addr, il, 1, True)
def _lift_MOV_S(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "fr"), il.reg(4, _reg_name(insn, "fs"))))
    return insn.length
def _lift_RFR(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "ar"), il.reg(4, _reg_name(insn, "fs"))))
    return insn.length
def _lift_WFR(insn, addr, il):
    il.append(il.set_reg(4, _reg_name(insn, "fr"), il.reg(4, _reg_name(insn, "as"))))
    return insn.length

# Float Compare operations
def _lift_float_compares(insn, addr, il, order, cond, merge):
    cond1 = order(4,il.reg(4, _reg_name(insn, "fs")), il.reg(4, _reg_name(insn, "ft")))
    cond2 = cond(4,il.reg(4, _reg_name(insn, "fs")), il.reg(4, _reg_name(insn, "ft")))
    il.append(il.set_reg(4, _reg_name(insn, "br"), merge(4, cond1, cond2)))
    return insn.length
def _lift_OEQ_S(insn, addr, il): 
    return _lift_float_compares(insn, addr, il, il.float_compare_ordered, il.float_compare_equal, il.and_expr)
def _lift_OLE_S(insn, addr, il): 
    return _lift_float_compares(insn, addr, il, il.float_compare_ordered, il.float_compare_less_equal, il.and_expr)
def _lift_OLT_S(insn, addr, il):
    return _lift_float_compares(insn, addr, il, il.float_compare_ordered, il.float_compare_less_than, il.and_expr)
def _lift_UEQ_S(insn, addr, il):
    return _lift_float_compares(insn, addr, il, il.float_compare_unordered, il.float_compare_equal, il.or_expr)
def _lift_ULE_S(insn, addr, il):
    return _lift_float_compares(insn, addr, il, il.float_compare_unordered, il.float_compare_less_equal, il.or_expr)
def _lift_ULT_S(insn, addr, il):
    return _lift_float_compares(insn, addr, il, il.float_compare_unordered, il.float_compare_less_than, il.or_expr)
def _lift_UN_S(insn, addr, il):
    cond1 = il. float_compare_unordered(4,il.reg(4, _reg_name(insn, "fs")), il.reg(4, _reg_name(insn, "ft")))
    il.append(il.set_reg(4, _reg_name(insn, "br"), cond1))
    return insn.length

# Float Loads and stores
def _lift_LSIU(insn, addr, il, update=True):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")),
                   il.const(4, insn.inline0(addr)))
    il.append(il.set_reg(4, _reg_name(insn, "ft"), il.load(4, va)))
    if update:
        il.append(il.set_reg(4, _reg_name(insn, "as"), va))
    return insn.length
def _lift_LSXU(insn, addr, il, update=True):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.reg(4, _reg_name(insn, "at")))
    il.append(il.set_reg(4, _reg_name(insn, "fr"), il.load(4, va)))
    if update:
        il.append(il.set_reg(4, _reg_name(insn, "as"), va))
    return insn.length


def _lift_SSIU(insn, addr, il, update=True):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")),
                   il.const(4, insn.inline0(addr)))
    il.append(il.store(4, va, il.reg(4, _reg_name(insn, "ft"))))
    if update:
        il.append(il.set_reg(4, _reg_name(insn, "as"), va))
    return insn.length
def _lift_SSXU(insn, addr, il, update=True):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.reg(4, _reg_name(insn, "at")))
    il.append(il.store(4, va, il.reg(4, _reg_name(insn, "fr"))))
    if update:
        il.append(il.set_reg(4, _reg_name(insn, "as"), va))
    return insn.length

def _lift_LSI(insn, addr, il):
    return _lift_LSIU(insn, addr, il, False)
def _lift_LSX(insn, addr, il):
    return _lift_LSXU(insn, addr, il, False)
def _lift_SSI(insn, addr, il):
    return _lift_SSIU(insn, addr, il, False)
def _lift_SSX(insn, addr, il):
    return _lift_SSXU(insn, addr, il, False)

#################################
# Boolean option Chapter 4.3.10 #
#################################
def _lift_anyall(insn, addr, il, op):
    s = _reg_name(insn, "bs")
    s_reg = il.reg(1, "b" + str(_reg_name(insn, "bs")))
    t_reg = il.reg(1, "b" + str(_reg_name(insn, "bt")))
    offset = int(op[-1]) # get the size of the instruction (4 or 8)
    
    temp = s_reg
    for idx in range(s+1, min(s+offset, 16)):
        if op[:-1] == "ALL":
            temp = il.and_expr(1, temp, il.reg(1, "b" + str(idx)))
        elif op[:-1] == "ANY":
            temp = il.or_expr(1, temp, il.reg(1, "b" + str(idx)))
        else:
            raise Exception("Wrong op used in _lift_anyall4. Can only use ANY4, ANY8, ALL4, ALL8, but op was " + op)

    il.append(il.set_reg(2, t_reg, temp))
    return insn.length

def _lift_ALL4(insn, addr, il):
    return _lift_anyall(insn, addr, il, "ALL4")
def _lift_ALL8(insn, addr, il):
    return _lift_anyall(insn, addr, il, "ALL8")
def _lift_ANY4(insn, addr, il):
    return _lift_anyall(insn, addr, il, "ANY4")
def _lift_ANY8(insn, addr, il):
    return _lift_anyall(insn, addr, il, "ANY8")

# Helper function to implement binary operations of boolean registers
def _lift_binop_B(insn, addr, il, op):
    r = il.reg(1, "b" + str(_reg_name(insn, "br")))
    t = il.reg(1, "b" + str(_reg_name(insn, "bt")))
    s = il.reg(1, "b" + str(_reg_name(insn, "bs")))
    
    bit_t_neg = il.not_expr(1, t) # Negate bit if necessary
    match op:
        case "ANDB":    temp = il.and_expr(1, s, t)
        case "ANDBC":   temp = il.and_expr(1, s, bit_t_neg)
        case "ORB":     temp = il.or_expr(1,  s, t)
        case "ORBC":    temp = il.or_expr(1,  s, bit_t_neg)
        case "XORB":    temp = il.xor_expr(1, s, t)
    il.append(il.set_reg(2, r, temp))
    return insn.length

def _lift_ANDB(insn, addr, il):
    return _lift_binop_B(insn, addr, il, "ANDB")
def _lift_ANDBC(insn, addr, il):
    return _lift_binop_B(insn, addr, il, "ANDBC")
def _lift_ORB(insn, addr, il):
    return _lift_binop_B(insn, addr, il, "ORB")
def _lift_ORBC(insn, addr, il):
    return _lift_binop_B(insn, addr, il, "ORBC")
def _lift_XORB(insn, addr, il):
    return _lift_binop_B(insn, addr, il, "XORB")

# Helper function for BF and BT, as only difference is the value of the condition
def _lift_BFT(insn, addr, il, bit):
    s = il.reg(1, "b" + str(_reg_name(insn, "bs")))
    
    cond = il.compare_equal(1, s, il.const(1, bit)) # 
    true_label, false_label = LowLevelILLabel(), LowLevelILLabel()

    il.append(il.if_expr(cond, true_label, false_label))
    il.mark_label(true_label)
    il.append(il.jump(il.const(4, insn.target_offset(addr))))
    il.mark_label(false_label)
    return insn.length

def _lift_BF(insn, addr, il):
    return _lift_BFT(insn, addr, il, 0)
def _lift_BT(insn, addr, il):
    return _lift_BFT(insn, addr, il, 1)

# Helper function for MOVF and MOVT, as only difference is the value of the condition
def _lift_MOVFT(insn, addr, il, bit, float):
    t = _reg_name(insn, "bt")
    t = il.reg(1, "b" + str(_reg_name(insn, "bt")))
    cond = il.compare_equal(1,  t, il.const(1, bit))
    return _lift_cmov(cond, insn, addr, il, float)
_lift_MOVF = lambda insn, addr, il: _lift_MOVFT(insn, addr, il, 0, False)
_lift_MOVT = lambda insn, addr, il: _lift_MOVFT(insn, addr, il, 1, False)

#########################################################
#### Miscellaneous Operations Option (Section 4.3.8) ####
#########################################################

def _lift_minmax(cond_func, left, right, insn, addr, il):
    """Helper for lifting min/max  operations 
    
    We pass in an IL condition (LowLevelILExpr), the right condition for min/max and
    the left and right operands. This will then lift the instruction using an if statement
    to branch based on the left and right values. left and right are both ExpressionIndex.
    Functions to use, where one needs to also pay attention to the signed/unnsigned version
    MAX -> greater_equal/greater 
    MIN -> lesser_equal/lesser
    """
    true_label = LowLevelILLabel()
    false_label = LowLevelILLabel()
    end_label = LowLevelILLabel()
    cond = cond_func(4, left, right)
    il.append(il.if_expr(cond, true_label, false_label))
    
    il.mark_label(true_label)
    il.append(il.set_reg(4, _reg_name(insn, "ar"), left))
    il.append(il.goto(end_label))
    
    il.mark_label(false_label)
    il.append(il.set_reg(4, _reg_name(insn, "ar"), right))
    il.append(il.goto(end_label))
    il.mark_label(end_label)
    return insn.length

def _lift_MAXU(insn, addr, il):
    return _lift_minmax(il.compare_unsigned_greater_equal,il.reg(4, _reg_name(insn, "as")), il.reg(4, _reg_name(insn, "at")), insn, addr, il)
def _lift_MAX(insn, addr, il):
    return _lift_minmax(il.compare_signed_greater_equal,  il.reg(4, _reg_name(insn, "as")), il.reg(4, _reg_name(insn, "at")), insn, addr, il)
def _lift_MIN(insn, addr, il):
    return _lift_minmax(il.compare_signed_less_equal,   il.reg(4, _reg_name(insn, "as")), il.reg(4, _reg_name(insn, "at")), insn, addr, il)
def _lift_MINU(insn, addr, il):
    return _lift_minmax(il.compare_unsigned_less_equal, il.reg(4, _reg_name(insn, "as")), il.reg(4, _reg_name(insn, "at")), insn, addr, il)

# Needs to compute : y ← min(max(x, − (2**imm)), 2imm−1)
def _lift_CLAMPS(insn, addr, il):
    x = il.reg(4, _reg_name(insn, "as")) 
    ar_reg = il.reg(4, _reg_name(insn, "ar")) 
    imm1 = il.const(4, - 2**(insn.t + 7))
    imm2 = il.const(4, 2**(insn.t + 7) - 1)

    underflow_label = LowLevelILLabel()
    overflow_label = LowLevelILLabel()
    value_label = LowLevelILLabel()
    false_label = LowLevelILLabel()
    end_label = LowLevelILLabel()

    cond = il.compare_signed_less_equal(4, x, imm1)
    il.append(il.if_expr(cond, underflow_label, false_label))
    
    # Underflow
    il.mark_label(underflow_label)
    il.append(il.set_reg(4, ar_reg, imm1))
    il.append(il.goto(end_label))
    
    il.mark_label(false_label)
    cond = il.compare_signed_greater_equal(4, x, imm2)
    il.append(il.if_expr(cond, overflow_label, value_label))

    # Overflow
    il.mark_label(overflow_label)
    il.append(il.set_reg(4, ar_reg, imm2))
    il.append(il.goto(end_label))

    # Value
    il.mark_label(value_label)
    il.append(il.set_reg(4, ar_reg, x))
    il.append(il.goto(end_label))

    il.mark_label(end_label)

    return insn.length

def _lift_SEXT(insn, addr, il):
    reg_as = il.reg(4, _reg_name(insn, "as"))
    reg_ar = il.reg(4, _reg_name(insn, "ar"))
    b = insn.inline0(addr)

    # To sign extend for a specific bit, we shift to the left until we reach
    # most significant bit, then use arightmetic right shift
    left_shifted = il.shift_left(4, reg_as, il.const(4, 31-b))
    result = il.arith_shift_right(4, left_shifted, il.const(4, 31-b))
    il.append(il.set_reg(4, _reg_name(insn, "at"),  result))
    return insn.length

# Placeholders for instructions NSA and NSAU for readability in code, 
# as implementing this in binja would result in a very convoluted code, 
# because it is not possible to access individual bits of a register
# TODO: get rid of placeholders and implement it yourself
def _lift_NSA(insn, addr, il):
    reg_as = il.reg(4, _reg_name(insn, "as"))
    reg_at = il.reg(4, _reg_name(insn, "at"))
    il.append(il.intrinsic([reg_at], "normalization_shift_amount", [reg_as]))
    return insn.length
def _lift_NSAU(insn, addr, il):
    reg_as = il.reg(4, _reg_name(insn, "as"))
    reg_at = il.reg(4, _reg_name(insn, "at"))
    il.append(il.intrinsic([reg_at], "normalization_shift_amount_unsigned", [reg_as]))
    return insn.length

##############################################
################ LOOP MODULE #################
##############################################

# TODO: Once function lifting feature is added, we can look into lifting Loop blocks which
#       span multiple basic blocks
def _lift_LOOP_simple(insn, addr, il):
    # Set constant we need for the function
    cnt = il.reg(4, _reg_name(insn, "as")) 
    end_addr = addr + 4 + insn.imm8
    false_label = LowLevelILLabel()
    begin_label = LowLevelILLabel()
    end_label = LowLevelILLabel()

    # Set registers
    il.append(il.set_reg(4, "lcount", cnt))
    il.append(il.set_reg(4, "lbeg", il.const(4, addr + 3)))
    il.append(il.set_reg(4, "lend", il.const(4, end_addr)))

    # Begin for loop
    # Check if loop if finished or not
    il.mark_label(begin_label)
    cond = il.compare_equal(4, il.reg(4, "lcount"), il.const(4, 0))
    il.append( il.if_expr(cond, end_label, false_label))

    # If false, we do keep going and decrease the counter
    il.mark_label(false_label)
    il.append( il.set_reg(4, "lcount", il.add(4, il.reg(4, "lcount"), il.const(4, -1))))
    # If true, we already jumped at the ened.


    # Jump to end and configure end loop
    il.set_current_address(end_addr)
    il.append(il.goto(begin_label))
    il.mark_label(end_label)

    # If loop is finished, branch
    il.set_current_address(addr)
    return insn.length

def _lift_loop_instruction(insn, addr, il, data, loop_type):
    # If we don't have enough data in insn, we can't lift the LOOP instruction
    # We need the whole block of the loop and the final instruction to be in the data
    # Require Function level lifting --> To be added in future Binja version
    if len(data) < insn.imm8 + 5:
        il.append(il.unimplemented())
        # return _lift_LOOP_simple(insn, addr, il)
        return insn.length
    
    # If the whole block in the data, we lift them all!
    # Set constant we need for the function
    cnt = il.reg(4, _reg_name(insn, "as")) 
    end_addr = addr + 4 + insn.imm8
    true_check_label = LowLevelILLabel()
    begin_label = LowLevelILLabel()
    false_label = LowLevelILLabel()
    end_label = LowLevelILLabel()

    # Set registers
    il.append(il.set_reg(4, "lcount", cnt))
    il.append(il.set_reg(4, "lbeg", il.const(4, addr + 3)))
    il.append(il.set_reg(4, "lend", il.const(4, end_addr)))

    if loop_type == "LOOP":
        cond = il.compare_equal(4, cnt, il.const(4, 0))
        
        il.append(il.if_expr(cond, true_check_label, begin_label))
        il.mark_label(true_check_label)
        il.append(il.set_reg(4, _reg_name(insn, "as"), il.const(4, 2**32)))
    

    # Begin for loop
    il.mark_label(begin_label)
    # Check if loop if finished or not
    # Checking for less equal will cover LOOPGTZ and LOOPNEZ conditions
    cond = il.compare_signed_less_equal(4, il.reg(4, "lcount"), il.const(4, 0))
    il.append( il.if_expr(cond, end_label, false_label))
    # If false, we keep going and decrease the counter
    il.mark_label(false_label)
    il.append( il.set_reg(4, "lcount", il.add(4, il.reg(4, "lcount"), il.const(4, -1))))

    # lift all instructions in the loop block
    curr_addr, curr_data = addr + 3, data[3:]
    total_len = insn.length
    while(curr_addr < end_addr):

        il.set_current_address(curr_addr)
        insn = None
        try:
            insn = Instruction.decode(curr_data)
        except:
            # Skip an instruction if you can't decode it
            curr_addr, curr_data = curr_addr + 3, curr_data[3:]
            continue
        insn_len = lift(insn, curr_addr, il)
        total_len += insn_len
        curr_addr, curr_data = curr_addr + insn_len, curr_data[insn_len:]

    # Jump to the beginning of the loop
    il.append(il.goto(begin_label))
    il.mark_label(end_label)
    return total_len

def _lift_LOOP(insn, addr, il, data):
    return _lift_loop_instruction(insn, addr, il, data, "LOOP")
def _lift_LOOPNEZ(insn, addr, il, data):
    return _lift_loop_instruction(insn, addr, il, data, "LOOPNEZ")
def _lift_LOOPGTZ(insn, addr, il, data):
    return _lift_loop_instruction(insn, addr, il, data, "LOOPGTZ")

##############################################
############# Exception Option ###############
##############################################

def _lift_ILL(insn, addr, il):
    # TODO: pick a proper trap constant
    il.append(il.trap(0))
    return insn.length
_lift_ILL_N = _lift_ILL

def _lift_SYSCALL(insn, addr, il):
    il.append(il.system_call())
    return insn.length

def _lift_EXCW(insn, addr, il):
    il.append(il.intrinsic([], "exception_wait", []))
    return insn.length


def _lift_RFE(insn, addr, il):
    dest = il.reg(4, 'epc1')
    il.append(il.ret(dest))
    return insn.length
_lift_RFUE = _lift_RFE
_lift_RFDE = _lift_RFE # TODO: include NDEPC as register (?) and use DEPC as destination if 1

##############################################
###### High-Priority Interrupt Option  #######
############ Interrupt Option  ###############
##############################################

def _lift_RFI(insn, addr, il):
    epc_level = il.reg(4, _reg_name(insn, "epcs"))
    il.append( il.set_reg(4, "ps",  epc_level))
    il.append(il.ret(epc_level))
    return insn.length

def _lift_RSIL(insn, addr, il):
    ps_reg = il.reg(4, "ps")
    il.append(il.set_reg(4, _reg_name(insn, "at"),  ps_reg))
    # TODO: ps.INTLEVEL = as
    return insn.length

# TODO: def _lift_WAITI

############################################################
######### Memory ECC/Parity Option #########################
############################################################
def _lift_RFME(insn, addr, il):
    dest = il.reg(4, 'mepc')
    il.append( il.set_reg(4, "ps",  il.reg(4, "meps")))
    # TODO: add MESR.MEME=0
    il.append(il.ret(dest))
    return insn.length


############################################################
######### MAC16 Option #####################################
############################################################
# TODO: LDDEC
# TODO: LDINC
# TODO: MUL.AA.*
# TODO: MUL.DA.*
# TODO: MUL.DD.*
# TODO: MULA.AA.*
# TODO: MULA.AD.*
# TODO: MULA.DA.*
# TODO: MULA.DA.*.LDDEC
# TODO: MULA.DA.*.LDINC
# TODO: MULA.DD.*
# TODO: MULA.DD.*.LDDEC
# TODO: MULA.DD.*.LDINC
# TODO: MULS.AA.*
# TODO: MULS.AD.*
# TODO: MULS.DA.*
# TODO: MULS.DD.*
# TODO: UMUL.AA.*

##############################################
#### Multiprocessor Synchronization Option ###
##############################################
# TODO: def _lift_L32AI
# TODO: def _lift_S32RI



#############################################################################
# Only instrinsics lifter instructions below
# These are instructions which deal with internal structures, such as 
# TLB and cache read, write, invalidate etc., so we just make them look
# like intrinsics call, as reproducing the exact behavior in the decompiler
# would be more confusing in practice.
# Below are some helper functions to make the code cleaner
#############################################################################

# Intrinsics of the form: function(index, value)
# Usually store some value at address at an index in a cache/TLB
def _lift_intrinsic_2param(insn, il, intrinsic):
    reg_as = il.reg(4, _reg_name(insn, "as"))
    reg_at = il.reg(4, _reg_name(insn, "at"))
    il.append(il.intrinsic([], intrinsic, [reg_as, reg_at]))
    return insn.length
# Intrinsics of the form: function(index)
# Usually load a value from index in a cache/TLB
def _lift_intrinsic_1param(insn, il, intrinsic):
    reg_as = il.reg(4, _reg_name(insn, "as"))
    il.append(il.intrinsic([], intrinsic, [reg_as]))
    return insn.length
# Intrinsics of the form: result=function(index)
# Usually load a value from index in a cache/TLB and store it in result
def _lift_intrinsic_1param_1result(insn, il, intrinsic):
    reg_as = il.reg(4, _reg_name(insn, "as"))
    reg_at = il.reg(4, _reg_name(insn, "at"))
    il.append(il.intrinsic([reg_at], intrinsic, [reg_as]))
    return insn.length

# Helper function to lift all data and instruction cache related option non-test instructions
# Here we also encode the virtual address according to the Reference Manual
def _lift_cache_intrinsic_imm8(insn, il, intrinsic):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.const(4, insn.imm8 << 2))
    il.append(il.intrinsic([], intrinsic, [va]))
    return insn.length
def _lift_cache_intrinsic_imm4(insn, il, intrinsic):
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.const(4, insn.imm4 << 4))
    il.append(il.intrinsic([], intrinsic, [va]))
    return insn.length

##############################################
######### Conditional Store Option ###########
##############################################
def _lift_S32C1I(insn, addr, il):
    reg_at = il.reg(4, _reg_name(insn, "at"))
    reg_scompare = il.reg(4, "scompare1")
    va = il.add(4, il.reg(4, _reg_name(insn, "as")), il.const(4, insn.imm8 << 2))
    il.append(il.intrinsic([reg_at], "store_32bit_compare_conditional", [va, reg_at, reg_scompare]))
    return insn.length

##############################################
################ Debug Option ################
##############################################

def _lift_BREAK(insn, addr, il):
    il.append(il.intrinsic([], "debug_break", []))
    return insn.length
_lift_BREAK_N = _lift_BREAK

# Used only in On-Chip Debug Mode
def _lift_RFDD(insn, addr, il):
    il.append(il.intrinsic([], "return_from_debug_and_dispatch", []))
    return insn.length
def _lift_RFDO(insn, addr, il):
    il.append(il.intrinsic([], "return_from_debug_operation", []))
    return insn.length

##############################################
############# Data Cache Option ##############
##############################################

_lift_DHI   = lambda insn, addr, il: _lift_cache_intrinsic_imm8(insn, il, "data_cache_hit_invalidate")
_lift_DHWB  = lambda insn, addr, il: _lift_cache_intrinsic_imm8(insn, il, "data_cache_hit_writeback")
_lift_DHWBI = lambda insn, addr, il: _lift_cache_intrinsic_imm8(insn, il, "data_cache_hit_writeback_invalidate")

_lift_DPFR  = lambda insn, addr, il: _lift_cache_intrinsic_imm8(insn, il, "data_cache_prefetch_for_read")
_lift_DPFRO = lambda insn, addr, il: _lift_cache_intrinsic_imm8(insn, il, "data_cache_prefetch_for_read_once")
_lift_DPFW  = lambda insn, addr, il: _lift_cache_intrinsic_imm8(insn, il, "data_cache_prefetch_for_write")
_lift_DPFWO = lambda insn, addr, il: _lift_cache_intrinsic_imm8(insn, il, "data_cache_prefetch_for_write_once")

_lift_DII   = lambda insn, addr, il: _lift_cache_intrinsic_imm8(insn, il, "data_cache_index_invalidate")
_lift_DIWB  = lambda insn, addr, il: _lift_cache_intrinsic_imm4(insn, il, "data_cache_index_writeback")
_lift_DIWBI = lambda insn, addr, il: _lift_cache_intrinsic_imm4(insn, il, "data_cache_index_writeback_invalidate")

##############################################
######## Data Cache Index Lock Option ########
##############################################

_lift_DHU  = lambda insn, addr, il: _lift_cache_intrinsic_imm4(insn, il, "data_cache_hit_unlock")
_lift_DIU  = lambda insn, addr, il: _lift_cache_intrinsic_imm4(insn, il, "data_cache_index_unlock")
_lift_DPFL = lambda insn, addr, il: _lift_cache_intrinsic_imm4(insn, il, "data_cache_prefetch_and_lock")

############################################################
######### Data Cache Test Option ###########################
############################################################

_lift_LDCT = lambda insn, addr, il: _lift_intrinsic_1param_1result(insn, il, "load_data_cache_tag")
_lift_SICT = lambda insn, addr, il: _lift_intrinsic_2param(insn, il, "store_data_cache_tag")

##############################################
########## Instruction Cache Option ##########
##############################################

_lift_IHI = lambda insn, addr, il: _lift_cache_intrinsic_imm8(insn, il, "instruction_cache_hit_invalidate")
_lift_III = lambda insn, addr, il: _lift_cache_intrinsic_imm8(insn, il, "instruction_cache_index_invalidate")
_lift_IPF = lambda insn, addr, il: _lift_cache_intrinsic_imm8(insn, il, "instruction_cache_prefetch")

##############################################
##### Instruction Cache Index Lock Option ####
##############################################

_lift_IHU  = lambda insn, addr, il: _lift_cache_intrinsic_imm4(insn, il, "instruction_cache_hit_unlock")
_lift_IIU  = lambda insn, addr, il: _lift_cache_intrinsic_imm4(insn, il, "instruction_cache_index_unlock")
_lift_IPFL = lambda insn, addr, il: _lift_cache_intrinsic_imm4(insn, il, "instruction_cache_prefetch_and_lock")

############################################################
######### Instruction Cache Test Option ####################
############################################################

_lift_LICT = lambda insn, addr, il: _lift_intrinsic_1param_1result(insn, il, "load_instruction_cache_tag")
_lift_LICW = lambda insn, addr, il: _lift_intrinsic_1param_1result(insn, il, "load_instruction_cache_word")
_lift_SICT = lambda insn, addr, il: _lift_intrinsic_2param(insn, il, "store_instruction_cache_tag")
_lift_SICW = lambda insn, addr, il: _lift_intrinsic_2param(insn, il, "store_instruction_cache_word")

##############################################
########### Region Protection Option #########
##############################################

_lift_IDTLB = lambda insn, addr, il: _lift_intrinsic_1param(insn, il, "invalidate_data_TLB_entry")
_lift_IITLB = lambda insn, addr, il: _lift_intrinsic_1param(insn, il, "invalidate_instruciton_TLB_entry")

##############################################
########## Region Translation Option #########
################### MMU Option ###############
##############################################

_lift_PDTLB = lambda insn, addr, il: _lift_intrinsic_1param_1result(insn, il, "probe_data_TLB")
_lift_PITLB = lambda insn, addr, il: _lift_intrinsic_1param_1result(insn, il, "probe_instruction_TLB")
_lift_RDTLB0 = lambda insn, addr, il: _lift_intrinsic_1param_1result(insn, il, "read_data_TLB_entry_virtual")
_lift_RDTLB1 = lambda insn, addr, il: _lift_intrinsic_1param_1result(insn, il, "read_data_TLB_entry_translation")
_lift_RITLB0 = lambda insn, addr, il: _lift_intrinsic_1param_1result(insn, il, "read_instruction_TLB_entry_virtual")
_lift_RITLB1 = lambda insn, addr, il: _lift_intrinsic_1param_1result(insn, il, "read_instruction_TLB_entry_translation")
_lift_WDTLB = lambda insn, addr, il: _lift_intrinsic_1param_1result(insn, il, "write_data_TLB_entry")
_lift_WITLB = lambda insn, addr, il: _lift_intrinsic_1param_1result(insn, il, "write_instruction_TLB_entry")

