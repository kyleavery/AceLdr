[BITS 64]

GLOBAL GetIp
GLOBAL Stub


[SECTION .text$C]

Stub:
    dq    0
    dq    0
    dq    0


[SECTION .text$F]

GetIp:
    call    get_ret_ptr

get_ret_ptr:
    pop    rax
    sub    rax, 5
    ret

Leave:
    db 'A', 'C', 'E', 'L', 'D', 'R'
