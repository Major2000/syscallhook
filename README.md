# Detect Hooked Syscalls

Enumerate which window API calls are hooked by an EDR using inline patching technique

# Walk through

## Function before hooking

Below shows the stub for for NtReadVirtualMemory on a system with no EDR present, meaning the syscall NtReadVirtualMemory is not hooked:
![Before hooking](/images/beforehook.png)

We can see the NtReadVirtualMemory syscall stub starts with instructions:

```
    00007ffc`d6dcc780 4c8bd1          mov     r10,rcx
    00007ffc`d6dcc783 b83f000000      mov     eax,3Fh
    ...
```

    The above applies to most routines starting with Zw, i.e ZwReadVirtualMemory too.

...which translates to the following 4 opcodes:

```
    4c 8b d1 b8
```

![opocodes](/images/4opocodes.png)
