# Makefile for SM4 C reference implementation.
# 在 MSYS2 UCRT64 或 Linux（CI）下直接 `make` 即可。

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
LDFLAGS ?=

# 编译时把 gcc 版本号注入 bench 输出
COMPILER_STR := $(shell $(CC) --version | head -n1)

SRCS_LIB  = sm4.c
OBJS_LIB  = $(SRCS_LIB:.c=.o)

.PHONY: all test bench clean

all: test_sm4 bench

%.o: %.c sm4.h constants.h
	$(CC) $(CFLAGS) -c $< -o $@

test_sm4: test_sm4.o $(OBJS_LIB)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bench: bench.o $(OBJS_LIB)
	$(CC) $(CFLAGS) -DSM4_COMPILER="\"$(COMPILER_STR)\"" -o $@ $^ $(LDFLAGS)

test: test_sm4
	./test_sm4

bench-run: bench
	./bench

clean:
	rm -f *.o test_sm4 bench test_sm4.exe bench.exe
