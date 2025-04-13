# Notes

- gcc has a xtensa  firmware plugin to create test codde
- espressif is a good starfting point, older cpu fr extensa, starting point of bin ninja
- focus on improving the python implemntation, as a full rewrite might be tedious and hard to debug.
https://github.com/Vector35/community-plugins
- most community plugins are written in python, so probably good to assume it is possible to achieve decent performance without the need of rewritting

- Everything is an expression tree. To lift instruction, use LowLevelILFunction functions and il.append(Expression) to chain

Firmwares to be loaded: max linear, ...

2 problems:
  load firmware into binja --> right section, all info, vector handling etc.
  ISA --> lifting to low level


WINDOW REGISTERS:


a0-a15 are a sliding window that reference 16 active registers at a time

callx4, callx8, callx12 move this sliding window

so after callx4, now a4 holds the stack pointer and we actually use physical registers a4-a19, but still mapped to a0-a15

Problem, I cant read the content of the register while actively decompiling...
Also problem, 3 different call functions for each increment value, only one retw, which depends on the value of the register


# Setup and Testing
To add the plugin to binja, just create a symlink to the source code in the plugins folder of binary ninja

God knows how I got here, but this kinda seems to work:
 xt-clang --xtensa-core=XRC_FusionF1_All_cache -c test_bin.S -o a.o

# Code structure:
__init__.py --> entry point for plugin, references filees: instruction.py, disassembly.py, lifter.py and binaryview.py
binaryview.py --> entry point for firmware_parser.py and known_symbols.py
dissassembly.py uses instruction.py
lifter.py uses instruction.py

# Code flow:
data loaded:
Instructions parsed
dissassembly code or lift instructions?


The separation of concerns between instruction decoding, disassembly, and
lifting is roughly as follows: anything that can be done without knowing the
address is done as part of instruction decoding. There might be a couple places
where I declare the computation with a lambda in decoding, which is called
during disassembly with the address. Anyway, all the decoding are static
methods.

# Current TODO:
 - Implement Windowed registers (Chapter 4.7.1): CallX4, callx8, rett4, rett8, entry, as it requires window shifts

# What is not implemented:

init:
 - No flags set since they are only used for floating points operations
 - get_instruction_info is missing some branch instructions (e.g. J.L)
 - Everything that is not dissassembled is also not lifted...

Loader problems, possible causes
 - A lot more to understand --> Firmware parser doesn't consider all possible firmware
 - LITBASE offset, set at the beginning of FW execution

Instruction file:
 - MAC16 instructions, deals with vector processor
 - Check _decode_ACCER bug: in manual we have RER=0000, WER=0111 --> maybe combine both to catch both behaviours
 - Come back to _decode_EXTUI once you understand the code base better 

Dissassembly file:
 - addi_n_imm could be replaced with an inline (?)
 - All float instructions:
    CLAMPS,  DHI, DHU, DHWB, DHWBI, DII, DIU, DIWB, DIWBI, DPFL, DPFR, DPFRO,
    LSI, LSIU, LSX, LSXU, MADD_S (floats)
 - Skipped instructions
    DPFW, DPFWO, they deal with data caching, which is an extension
    IHI, IHU, III, IIU, IPF, IPFL, windowed L32E, LDCT, 
    LDDEC,LDINC; they're MAC16
    LICT, LICW, instruction cache option
    LOOP, LOOPGTZ, LOOPNEZ, loop option
    WUR --> Check if it works



# Problems encountered:
 - MULL instruction gets assigned a different opcode by the xt-clang compiler. It's the length of 2 3-byte instrucitons: 25 70 fe f1 9f 58 (Assembbly mull a2, a8, a5 )
 - This happens to many floating point operations as well...
