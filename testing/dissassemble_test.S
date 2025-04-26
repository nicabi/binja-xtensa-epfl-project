.text
.align 4
.global main
main:
    entry a1, 16
    abs a4, a7
    abs.s aed2, aed11
    add a6, a1, a9
    add.n a3, a12, a2
    add.s aed5, aed7, aed5
    addi a8, a5, -37          # -128..127
    addi.n a9, a6, 14         # -1 or 1..15
    addmi a2, a11, 0x3000     # multiple of 256 in -32768..32512
    addx2 a4, a15, a1
    addx4 a7, a13, a3
    addx8 a5, a3, a6
    all4 b4, b0               # b0, b4, b8, b12 only
    all8 b1, b8               # b0 or b8 only
    and a7, a4, a2
    andb b3, b1, b5
    andbc b0, b7, b2
    any4 b12, b4              # b0, b4, b8, b12 only
    any8 b0, b8               # b0 or b8 only
    ball a5, a3, main
    bany a2, a6, main
    bbc a7, a1, main
    bbci a0, 22, main       # 0..31
    bbci.l a4, 3, main      # 0..31, bit number
    bbs a6, a5, main
    bbsi a2, 17, main       # 0..31
    bbsi.l a3, 12, main     # 0..31
    beq a1, a7, main
    beqi a0, 4, main        # valid encoded constant (e.g., from B4CONST)
    beqz a6, main
    beqz.n a3, main


    bf b0, main
    bge a5, a6, main
    bgei a7, 0, main
    bgeu a8, a9, main
    bgeui a10, 3, main
    bgez a11, main
    blt a12, a13, main
    blti a14, 2, main
    bltu a15, a1, main
    bltui a2, 2, main
    bltz a3, main
    bnall a4, a5, main
    bne a6, a7, main
    bnei a8, 5, main
    bnez a9, main
    bnez.n a10, main
    bnone a11, a12, main
    break 1, 2
    break.n 0
    bt b1, main
    call0 main
    call4 main
    call8 main
    call12 main
    callx0 a2
    callx4 a3
    callx8 a4
    callx12 a5
    clamps a7, a8, 8
    dhi a9, 4
    dhu a10, 16
    dhwb a11, 12
    dhwbi a12, 16
    dii a13, 20
    diu a14, 0
    diwb a15, 0
    diwbi a1, 32
    dpfl a2, 0
    dpfr a3, 40
    dpfro a4, 44
    dpfw a5, 48
    dpfwo a6, 52
    dsync

    esync
    excw
    extui a7, a8, 4, 8
    extw
    idtlb a11
    ihi a12, 0
    ihu a13, 0
    iii a14, 12
    iitlb a15
    iiu a1, 16
    ill
    ill.n
    ipf a2, 20
    ipfl a3, 0
    isync 
    l8ui a6, a7, 1
    l16ui a8, a9, 2
    l16si a10, a11, 3
    l32ai a12, a13, 4
    l32e a14, a15, -64
    l32i a1, a2, 8
    l32i.n a3, a4, 0
    l32r a5, main
    ldct a6, a7
    lict a14, a15
    licw a1, a2
    


	madd.s aed6, aed1, aed0
    max a9, a5, a1
    maxu a13, a3, a14
    memw
    min a0, a8, a7
    minu a4, a6, a2
    mov a12, a1
    mov.n a5, a6
    moveqz a15, a0, a10
    moveqz.s aed6, aed5, a11
    movf a8, a2, b0
    movf.s aed1, aed3, b6
    movgez a9, a4, a7
    movgez.s aed2, aed0, a10
    movi a5, 0x1234
    movi.n a14, 9
    movltz a7, a6, a13
    movltz.s aed5, aed3, a12
    movnez a10, a11, a1
    movnez.s aed4, aed7, a8
    movsp a15, a2
    movt a0, a3, b7
    movt.s aed3, aed6, b2
    msub.s aed1, aed2, aed5
    mul.s aed0, aed2, aed6
    
    
    neg a3, a15
    neg.s aed5, aed1
    nop
    nop.n
    nsa a10, a4
    nsau a0, a11
    oeq.s b3, aed6, aed7
    ole.s b4, aed1, aed0
    olt.s b5, aed2, aed4
    or a6, a1, a9
    orb b2, b6, b1
    orbc b7, b3, b4
    pdtlb a8, a13
    pitlb a0, a7
    rdtlb0 a6, a9
    rdtlb1 a2, a10
    rer a13, a2  
    rfdd
    rfde
    rfe
    rfi 1
    rfr a4, aed3
    rfwo
    rfwu
    ritlb0 a11, a5
    ritlb1 a6, a9
    rotw 4
    rsil a10, 3
    rsr a0, lbeg
    rsync
    s8i a7, a4, 1
    s16i a6, a12, 2
    s32c1i a5, a10, 4
    s32e a15, a14, -16
    s32i a8, a3, 8
    s32i.n a13, a9, 0
    s32ri a1, a5, 12
    sdct a11, a6
    sext a2, a4, 8
    sict a3, a10
    sicw a12, a15
    sll a4, a3
    slli a13, a0, 3
    sra a5, a8
    srai a11, a6, 5
    src a9, a3, a10
    srl a15, a4
    srli a1, a13, 7
    ssa8b a7
    ssa8l a6
    ssai 15
    ssl a13
    ssr a3        
    sub a0, a4, a7
    sub.s aed6, aed5, aed2
    subx2 a3, a9, a14
    subx4 a8, a1, a10
    subx8 a11, a6, a13
    syscall
    ule.s b7, aed2, aed1
    ult.s b0, aed4, aed6
    un.s b1, aed3, aed0
    waiti 4
    wdtlb a6, a14
    wer a3, a7
    wfr aed7, a11
    witlb a4, a9
    wsr a5, lbeg
    xsr a3, lend
    xor a1, a12, a3
    xorb b4, b2, b6

    # Obscure instrucitons:
    # rur  a1, windowbase                   # Format unclear, requires TIE compiler too? Multiprocessor
    # wur windowbase, a0                    # Format unclear, requires TIE compiler too? Multiprocessor
    # rfdo                                  # Can't compile it - not enough operands, debug options, illegal if chip not in debug mode --> useless.
    # rfme                                  # Can't compile - unknown opcode or format
    # rfue                                  # Can't compile - unknown opcode or format


    # Floating operations get compiled with multiple instructions for some reason
    # trunc.s aed2, aed0, 0
    # ueq.s b6, aed3, aed7
    # ufloat.s aed5, aed4, 0
    # utrunc.s aed10, aed2, 0
    # lsi aed8, aed6, 0       # Can't compile it - unknown opcode???
    # lsiu aed1, a7, 20       # Can't compile it - unknown opcode???
    # lsx aed2, aed7, aed5    # Can't compile it - unknown opcode???
    # lsxu aed3, aed4, aed3   # Can't compile it - unknown opcode???
    # mov.s aed7, aed4         # Can't compile it - unknown opcode???
    # ceil.s aed6, aed0, 0  # Can't compile it - unknown opcode???
    # float.s aed1, aed7, 0     # Binja doesnt want to decompile it...
    # floor.s a0, a0, 0         # Can't compile it - unknown opcode???
    # round.s aed2, aed6, 4                 # Can't compile - unknown opcode or format
    # ssi aed0, aed4, 16                    # Can't compile - unknown opcode or format      
    # ssiu aed4, aed7, 20                   # Can't compile - unknown opcode or format      
    # ssx aed1, aed5, aed2                  # Can't compile - unknown opcode or format      
    # ssxu aed3, aed14, aed6                # Can't compile - unknown opcode or format  

    # Integer multiplicaiton module
    # mull a2, a8, a5                          # Compiler is using a weird OP code for this instruction...
    # mulsh a7, a13, a2                        # Compiler is using a weird OP code for this instruction... 
    # muluh a6, a5, a1                         # Compiler is using a weird OP code for this instruction... 
    
    # Integer Divide module
    # quos a5, a12, a11                        # Can't compile it - unknown opcode???
    # quou a4, a3, a15                         # Can't compile it - unknown opcode???
    # rems a1, a7, a8                          # Can't compile it - unknown opcode???
    # remu a12, a0, a14                        # Can't compile it - unknown opcode???

    # MAC16 operations:
    # mul.aa.ll a6, a14                        # Can't compile it - unknown opcode/format - MAC16 option
    # mul.da.ll a11, a13                       # Can't compile it - unknown opcode/format - MAC16 option
    # mul.dd.ll a3, a7                         # Can't compile it - unknown opcode/format - MAC16 option
    # mul16u a1, a9, a15                       # Can't compile it - unknown opcode/format - MAC16 option
    # mul16s a4, a10, a12                      # Can't compile it - unknown opcode/format - MAC16 option
    # mula.aa.ll a5, a0                        # Can't compile it - unknown opcode/format - MAC16 option
    # mula.ad.ll a7, a6                        # Can't compile it - unknown opcode/format - MAC16 option
    # mula.da.ll a14, a3                       # Can't compile it - unknown opcode/format - MAC16 option
    # mula.da.ll.lddec a10:a13, a2, a6, a7     # Can't compile it - unknown opcode/format - MAC16 option
    # mula.da.ll.ldinc a8:a12, a5, a4, a9      # Can't compile it - unknown opcode/format - MAC16 option
    # mula.dd.ll a15, a11                      # Can't compile it - unknown opcode/format - MAC16 option
    # mula.dd.ll.lddec a1:a0, a3, a5, a10      # Can't compile it - unknown opcode/format - MAC16 option
    # mula.dd.ll.ldinc a6:a13, a14, a4, a7     # Can't compile it - unknown opcode/format - MAC16 option
    # muls.aa.ll a1, a11                       # Can't compile it - unknown opcode/format - MAC16 option
    # muls.ad.ll a10, a3                       # Can't compile it - unknown opcode/format - MAC16 option
    # muls.da.ll a12, a9                       # Can't compile it - unknown opcode/format - MAC16 option
    # muls.dd.ll a4, a14                       # Can't compile it - unknown opcode/format - MAC16 option
    # umul.aa.ll a5, a13                       # Can't compile - unknown opcode or format - MAC16 option
    # lddec a8:a9, a10                         # MAC16 - TODO
    # ldinc a11M:a12, a13


    # Other instructions
    # j main                # Should be tested separately        
    # j.l main, a4          # Should be tested separately            
    # jx a5                 # Should be tested separately   
    # loop a3, main       # needs proper code for testing
    # loopnez a4, main     # needs proper code for testing
    # loopgtz a5, main     # needs proper code for testing
    # ret                                   # Commented - Should be tested separately  
    # ret.n                                 # Commented - Should be tested separately  
    # retw                                  # Commented - Should be tested separately  
    # retw.n                                # Commented - Should be tested separately    
    ret

.size main, .-main