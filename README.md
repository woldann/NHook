# NHook

NHook is a minimal and efficient inline hooking library for Windows x64.  
It aims to provide inline hooking similar to MinHook but allows calling the original function without creating a trampoline, achieving the same effect with minimal code changes.

## Features

- **Minimal inline hook**: Replaces only 2 bytes at the start of the hook with an infinite loop (`jmp $` — `EB FE`)
- **Call original function without trampoline**: Original function can be called without the need for a trampoline
- **Cross-process support**: Hook functions in another process and invoke them via NThread
- **Instruction simulation**: Supports common x86_64 instructions (MOV, LEA, ADD, SUB, INC, DEC, XOR, etc.)

## Requirements

- Windows x64 system (target)
- CMake 3.10 or higher
- MinGW-w64 (for cross-compilation)
- Ninja build system (recommended)

## Building

Install required packages:
```bash
sudo apt install mingw-w64 cmake ninja-build
```

Clone and initialize submodules:
```bash
git submodule update --init
```

Build the project:
```bash
cmake -B build -G Ninja \
  -DCMAKE_SYSTEM_NAME=Windows \
  -DCMAKE_C_COMPILER=/usr/bin/x86_64-w64-mingw32-gcc \
  -DCMAKE_CXX_COMPILER=/usr/bin/x86_64-w64-mingw32-g++ \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Usage Example

```c
nhook_manager_t *manager = nh_create_manager(GetCurrentProcessId(), 10);

// Target function to hook
int target_function(int count) {
    return count * 2;
}

// Hook function
int hook_function(int count) {
    printf("Hooked! Count: %d\n", count);
    return (int)(intptr_t)nh_trampoline(manager, hook_function, count);
}

nh_create(manager, target_function, hook_function, 1);
nh_enable_all(manager);

// Create thread to call hooked function
CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)target_function, (LPVOID)5, 0, NULL);

// Update hooks in main thread
while (true) {
    nh_update(manager);
    Sleep(10);
}
```

## Limitations

- Floating point arguments not supported
- Windows x64 only
- Care needed when handling pointers across processes

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.md) file for details.