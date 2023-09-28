CC_X64      := x86_64-w64-mingw32-gcc
NAME        := AceLdr
OUT         := bin

CFLAGS      := $(CFLAGS) -Os -fno-asynchronous-unwind-tables -nostdlib 
CFLAGS      := $(CFLAGS) -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS      := $(CFLAGS) -s -ffunction-sections -falign-jumps=1 -Wall
CFLAGS      := $(CFLAGS) -Werror -falign-labels=1 -fPIC -Wno-array-bounds
LFLAGS      := $(LFLAGS) -Wl,-s,--no-seh,--enable-stdcall-fixup
LFLAGS 		:= $(LFLAGS) -Wl,--image-base=0,-Tsrc/link.ld


default: clean aceldr
release: default zip

aceldr:
	@ nasm -Werror=all -f win64 src/asm/start.asm -o $(OUT)/start.tmp.o
	@ nasm -Werror=all -f win64 src/asm/misc.asm -o $(OUT)/misc.tmp.o
	@ nasm -Werror=all -f win64 src/asm/spoof.asm -o $(OUT)/spoof.tmp.o
	@ $(CC_X64) src/*.c $(OUT)/start.tmp.o $(OUT)/misc.tmp.o $(OUT)/spoof.tmp.o src/hooks/*.c -o $(OUT)/$(NAME).x64.exe $(CFLAGS) $(LFLAGS) -I.
	@ python3 scripts/extract.py -f $(OUT)/$(NAME).x64.exe -o $(OUT)/$(NAME).x64.bin
	@ rm $(OUT)/*.tmp.o 2>/dev/null || true
	@ rm $(OUT)/$(NAME).x64.exe 2>/dev/null || true

clean:
	@ rm $(OUT)/*.o 2>/dev/null || true
	@ rm $(OUT)/*.exe 2>/dev/null || true
	@ rm $(OUT)/*.bin 2>/dev/null || true
	@ rm $(NAME).zip 2>/dev/null || true

zip:
	@ zip $(NAME).zip $(OUT)/*
