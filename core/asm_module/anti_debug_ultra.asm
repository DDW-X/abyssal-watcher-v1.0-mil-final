
section .text
    global _start

_start:
    ; --------- روش‌های تشخیص دیباگر ---------

    ; 1. بررسی بایت int3 (0xCC) در حافظه
    call get_eip
get_eip:
    pop eax
    mov byte [eax], 0xCC
    cmp byte [eax], 0xCC
    je debugger_found

    ; 2. بررسی پرچم Trap Flag در EFLAGS (تشخیص single-step)
    pushfd
    pop eax
    test eax, 0x100
    jnz debugger_found

    ; 3. بررسی زمان اجرای rdtsc (خیلی سریع‌تر در حالت عادی)
    rdtsc
    mov esi, eax
    rdtsc
    sub eax, esi
    cmp eax, 100
    jl not_debugged
    jmp debugger_found

not_debugged:
    ; هیچ دیباگری یافت نشد، اجرای برنامه ادامه دارد
    mov eax, 1
    mov ebx, 0
    int 0x80

debugger_found:
    ; دیباگر یافت شد، بستن برنامه و پاک کردن اثر
    mov eax, 1
    mov ebx, 255
    int 0x80
