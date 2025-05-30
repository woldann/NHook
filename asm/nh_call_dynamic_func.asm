section .text
global nh_call_dynamic_func

nh_call_dynamic_func:
    push rbp
    mov rbp, rsp
    sub rsp, 32

    movzx rbx, dl
    mov rsi, r8
    mov rax, rcx

    test rbx, rbx
    jz call_func

    mov rcx, [rsi]
    cmp rbx, 1
    jle call_func

    mov rdx, [rsi + 8]
    cmp rbx, 2
    jle call_func

    mov r8, [rsi + 16]
    cmp rbx, 3
    jle call_func

    mov r9, [rsi + 24]
    cmp rbx, 4
    jle call_func

    sub rbx, 5
    lea rsi, [rsi + 32]

push_loop:
    cmp rbx, -1
    jle call_func

    mov rdi, [rsi + rbx*8]
    push rdi
    dec rbx
    jmp push_loop

call_func:
    sub rsp, 32
    call rax

    mov rsp, rbp
    pop rbp
    ret
