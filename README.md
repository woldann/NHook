# NHook

NHook is a minimal and efficient inline hooking library for Windows x64.  
It aims to provide inline hooking similar to MinHook but allows calling the original function without creating a trampoline, achieving the same effect with minimal code changes.

---

## Features

- **Minimal inline hook**: Replaces only 2 bytes at the start of the hook with an infinite loop (`jmp $` — `EB FE`).
- **Call original function without trampoline**: Original function can be called without the need for a trampoline.
- Hook functions in another process and invoke them in your own process via NThread, passing arguments carefully.
- Argument count must be specified when creating the hook.
- Slightly slower than MinHook but requires significantly less code modification.
- Supports cross-compilation from Linux (using MinGW) and native build on Windows.

---

## How It Works

- The first 2 bytes of the target function are replaced with an infinite loop (`jmp $`).
- Threads that hit this loop are intercepted and initialized via `NThread`.
- When calling the original function, the modified instructions within those 2 bytes are executed remotely via `NThread`, then a jump is made to the unaffected remainder of the original function.
- This way, the original function is called without creating a trampoline.
- Hooks can be applied across processes, but argument handling requires caution, especially with pointers and references.
- Note: Floating point arguments (`float` and `double`) are currently not supported.

---

## Build Instructions

### On Linux (cross-compiling for Windows)

```bash
cmake -B build -G Ninja \
  -DCMAKE_SYSTEM_NAME=Windows \
  -DCMAKE_C_COMPILER=/usr/bin/x86_64-w64-mingw32-gcc \
  -DCMAKE_CXX_COMPILER=/usr/bin/x86_64-w64-mingw32-g++ \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### On Windows

```bash
cmake -B build -G "Ninja" -DCMAKE_BUILD_TYPE=Release
cmake --build build
```
