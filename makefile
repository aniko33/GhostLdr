CFLAGS = -Iinclude
OBJ = target/main.o target/shellcode.o target/evasion.o target/vse.o target/syscalls.o target/cargo.o
all: target/ghost.exe

clean:
	rm -rf target/*

target/cargo.o: ./shellcode.encrypted src/shellcode/cargo.h
	objcopy --input-target=binary --binary-architecture=i386:x86-64 --output-target=pei-x86-64 shellcode.encrypted target/cargo.o
	objcopy --redefine-sym _binary_shellcode_encrypted_start=shellcode_start --redefine-sym _binary_shellcode_encrypted_end=shellcode_end --redefine-sym _binary_shellcode_encrypted_size=shellcode_size target/cargo.o

target/main.o: src/main.c target/cargo.o
	x86_64-w64-mingw32-gcc $(CFLAGS) src/main.c -c -o target/main.o

target/syscalls.o: src/syscalls/syscalls.c src/syscalls/syscalls.h
	x86_64-w64-mingw32-gcc $(CFLAGS) src/syscalls/syscalls.c -c -o target/syscalls.o

target/vse.o: src/syscalls/vse.asm
	nasm -f win64 src/syscalls/vse.asm -o target/vse.o

target/evasion.o: src/evasion/evasion.c src/evasion/evasion.h
	x86_64-w64-mingw32-gcc $(CFLAGS) src/evasion/evasion.c -c -o target/evasion.o

target/shellcode.o: src/shellcode/shellcode.c src/shellcode/shellcode.h
	x86_64-w64-mingw32-gcc $(CFLAGS) src/shellcode/shellcode.c -c -o target/shellcode.o

target/ghost.exe: target/main.o target/shellcode.o target/evasion.o target/vse.o target/syscalls.o
	x86_64-w64-mingw32-gcc $(CFLAGS) $(OBJ) -o target/ghost.exe -lws2_32 -lntdll -mwindows
