#ifndef SHELLCODE_H
#define SHELLCODE_H

uint8_t* RollbackShellcode(const uint8_t* buf, const uint8_t key, size_t bufLen, size_t* outLen);

#endif
