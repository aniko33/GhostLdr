section .text
    global ExecuteVSE

ExecuteVSE:
    int 0x3
    ret
