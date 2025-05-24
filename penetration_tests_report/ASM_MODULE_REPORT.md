# Assembly Module: Anti-Debug

## Purpose
This module uses x86 assembly to detect simple debugging attempts by inspecting the Trap Flag (TF) in the FLAGS register.

## Code Overview
```asm
pushf
pop ax
and ax, 0x0100
jz not_debugged
```

If TF is set, it assumes a debugger is present.

## Result
- Integrated into the core system
- Linked with Rust/C modules using FFI
- Passed testing under simulated debugger environments
