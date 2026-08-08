CC       = gcc
CFLAGS   = -Wall -Wextra -O2 -g -Iinclude
LDFLAGS  =
RM       = rm -f

# 所有测试目标
TESTS = tests/test_aead tests/test_pbkdf2 tests/test_x25519

# 所有 .c 源文件（不包括测试）
SRCS = $(wildcard src/*.c src/kdf/*.c src/sha2/*.c src/x25519/*.c src/xchacha20poly1305/*.c)
SRCS := $(filter-out src/test.c, $(SRCS))

# 所有 .o 文件
OBJS = $(patsubst %.c,%.o,$(SRCS))

all: $(TESTS)

# 每个测试的编译规则
tests/test_aead: tests/test_aead.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

tests/test_pbkdf2: tests/test_pbkdf2.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

tests/test_x25519: tests/test_x25519.c $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 通用 .o 编译
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJS) $(TESTS)

.PHONY: all clean