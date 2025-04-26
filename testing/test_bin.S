.text
.align 4

.global main
main:
    # Bitwise boolean operations
    ANDB  b2, b1, b0
    ANDBC b2, b1, b0
    ORB   b2, b1, b0
    ORBC  b2, b1, b0
    XORB  b2, b1, b0

    # Bit field tests
    ALL4  b0, b4
    ALL8  b0, b8
    ANY4  b0, b4
    ANY8  b0, b8

    # Branch and move operations
    BT    b2, true
    BF    b2, false

true:
    MOVT  a3, a4, b5

    # Print a3 via syscall
    mov   a2, a3        # put a3 in syscall arg register
    movi  a3, 1         # syscall number (assumed)
    syscall

    RET

false:
    MOVF  a3, a4, b6

    # Print a3 via syscall
    mov   a2, a3
    movi  a3, 1
    syscall

    RET

.size main, .-main
