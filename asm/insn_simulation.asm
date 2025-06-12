section .text
global simulate_add
global simulate_sub
global simulate_xor
global simulate_cmp
global simulate_test

simulate_add:
    movzx rax, r8b
    cmp rax, 1
    je  add_1
    cmp rax, 2
    je  add_2
    cmp rax, 4
    je  add_4
    cmp rax, 8
    je  add_8

    xor eax, eax
    ret
add_1:
    add cl, dl
    mov byte [r9], cl
    jmp flags_read

add_2:
    add cx, dx
    mov word [r9], cx
    jmp flags_read

add_4:
    add ecx, edx
    mov dword [r9], ecx
    jmp flags_read

add_8:
    add rcx, rdx
    mov qword [r9], rcx
    jmp flags_read

simulate_sub:
    movzx rax, r8b
    cmp rax, 1
    je  sub_1
    cmp rax, 2
    je  sub_2
    cmp rax, 4
    je  sub_4
    cmp rax, 8
    je  sub_8

    xor eax, eax
    ret
sub_1:
    sub cl, dl
    mov byte [r9], cl
    jmp flags_read

sub_2:
    sub cx, dx
    mov word [r9], cx
    jmp flags_read

sub_4:
    sub ecx, edx
    mov dword [r9], ecx
    jmp flags_read

sub_8:
    sub rcx, rdx
    mov qword [r9], rcx

flags_read:
    pushfq
    pop rax
    ret

simulate_xor:
    movzx rax, r8b
    cmp rax, 1
    je  xor_1
    cmp rax, 2
    je  xor_2
    cmp rax, 4
    je  xor_4
    cmp rax, 8
    je  xor_8

    xor eax, eax
    ret
xor_1:
    xor cl, dl
    mov byte [r9], cl
    jmp flags_read

xor_2:
    xor cx, dx
    mov word [r9], cx
    jmp flags_read

xor_4:
    xor ecx, edx
    mov dword [r9], ecx
    jmp flags_read

xor_8:
    xor rcx, rdx
    mov qword [r9], rcx
    jmp flags_read

simulate_cmp:
    movzx rax, r8b
    cmp rax, 1
    je  cmp_1
    cmp rax, 2
    je  cmp_2
    cmp rax, 4
    je  cmp_4
    cmp rax, 8
    je  cmp_8

    xor eax, eax
    ret
    
cmp_1:
    cmp cl, dl
    jmp flags_read

cmp_2:
    cmp cx, dx
    jmp flags_read

cmp_4:
    cmp ecx, edx
    jmp flags_read

cmp_8:
    cmp rcx, rdx
    jmp flags_read

simulate_test:
    movzx rax, r8b
    cmp rax, 1
    je  test_1
    cmp rax, 2
    je  test_2
    cmp rax, 4
    je  test_4
    cmp rax, 8
    je  test_8

    xor eax, eax
    ret
    
test_1:
    test cl, dl
    jmp flags_read

test_2:
    test cx, dx
    jmp flags_read

test_4:
    test ecx, edx
    jmp flags_read

test_8:
    test rcx, rdx
    jmp flags_read

