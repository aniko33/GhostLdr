#ifndef SYSCALLS_H
#define SYSCALLS_H

typedef struct {
    PVOID                   SyscallAddr;
    PIMAGE_DOS_HEADER       Base;
    PIMAGE_EXPORT_DIRECTORY Exports;
} CTX_VSE;

extern NTSTATUS NTAPI ExecuteVSE(...);
extern CTX_VSE GlobalVSE;

CTX_VSE InitVSE();
BOOL    GetFunctionAddr(CTX_VSE* ctx, char* functionName);
int     GetSyscallAddr(VOID* fSyscallAddr, INT_PTR* outAddr);
ULONG   CALLBACK SyscallRunnerVEH(PEXCEPTION_POINTERS exception);

#define INIT_VSE(CALLBACK, OUT) \
    AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)CALLBACK); \
    OUT = InitVSE()

#define EXECUTE_VSE(CTX, FUNC, OUT, ...) \
    if (!GetFunctionAddr(&CTX, FUNC)) return -1; \
    OUT = ExecuteVSE( __VA_ARGS__ )

#endif
