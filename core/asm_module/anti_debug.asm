
section .text
    global _start

_start:
    ; چک برای دیباگر ساده با بررسی پرچم TF در فلگ رجیستر
    pushf
    pop ax
    and ax, 0x0100
    jz not_debugged

debugged:
    mov dx, 0xDEAD
    jmp end

not_debugged:
    mov dx, 0xBEEF

end:
    mov ax, 0x4C00
    int 0x21
