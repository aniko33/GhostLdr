#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

//
// From Ghosty encryption
//

uint8_t* NibbleDecode(const uint8_t* buf, size_t bufSize, size_t* outLen) {
    uint8_t* outBuf = malloc(bufSize / 2);
    if (outBuf == NULL) return NULL;

    for (int i = 0, j = 0; i < bufSize; i+=2) {
        uint8_t hi = buf[i] - 0x40;
        uint8_t lo = buf[i + 1] - 0x50;

        outBuf[j++] = ((hi & 0xF) << 4 | (lo & 0xF));
    }

    *outLen = bufSize / 2;
    return outBuf;
}

void XorEncryptDecrypt(uint8_t* buf, uint8_t key, size_t bufLen) {
    for (int i = 0; i < bufLen; i++) {
        buf[i] = buf[i] ^ key;
        key = (key + 1) & 0xFF;
    }
}

uint8_t* YEncDecode(const uint8_t* buf, size_t bufLen, size_t* outLen) {
    uint8_t* outBuf = malloc(bufLen);
    if (outBuf == NULL) return NULL;

    size_t cursor = 0;
    for (int i = 0; i < bufLen; i++) {
        uint8_t c = buf[i];

        if (c == '\r' || c == '\n') {
            continue;
        }

        if (c == '=') {
            i++;
            if (i >= bufLen) {
                free(outBuf);
                return NULL;
            }
            c = (c - 64) % 256;
        }
        c = (c - 42) % 256;
        outBuf[cursor++] = c;
    }

    *outLen = cursor;
    return outBuf;
}

uint8_t* RLEDecompress(const uint8_t* buf, size_t bufLen, size_t* outLen) {
    if (bufLen & 1) return NULL;

    size_t capacity = 0;
    for (size_t i = 0; i + 1 < bufLen; i += 2) {
        capacity += buf[i];
    }

    uint8_t* outBuf = malloc(capacity);
    if (outBuf == NULL) return NULL;

    size_t pos = 0;
    for (size_t i = 0; i + 1 < bufLen; i += 2) {
        uint8_t count = buf[i];
        uint8_t val   = buf[i+1];
        memset(outBuf + pos, val, count);
        pos += count;
    }

    *outLen = pos;
    return outBuf;
}

uint8_t* RollbackShellcode(const uint8_t* buf, const uint8_t key, size_t bufLen, size_t* outLen) {
    uint8_t* shellcodeStep1 = YEncDecode(buf, bufLen, outLen);
    uint8_t* shellcodeStep2 = NibbleDecode(shellcodeStep1, *outLen, outLen);
    free(shellcodeStep1);
    uint8_t* shellcodeStep3 = RLEDecompress(shellcodeStep2, *outLen, outLen);
    free(shellcodeStep2);
    XorEncryptDecrypt(shellcodeStep3, key, *outLen);

    return shellcodeStep3;
}
