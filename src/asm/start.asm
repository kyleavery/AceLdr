[BITS 64]

EXTERN Ace
GLOBAL Start

[SECTION .text$A]

Start:
    push   rsi
    mov    rsi, rsp
    and    rsp, 0FFFFFFFFFFFFFFF0h
    sub    rsp, 020h
    call   Ace
    mov    rsp, rsi
    pop    rsi
    ret
