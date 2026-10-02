# MSYS2 / MinGW (POSIX shell, Windows PE output).

BUILD_DIR = build/win
EXE = .exe
SO_EXT = .dll
IMPLIB_EXT = .dll.a
AR = ar
LDFLAGS = -lm -lbcrypt
SO_LDFLAGS = -Wl,--out-implib,$(LIB_DIR)/libsdcrypt$(IMPLIB_EXT)
TEST_RUN_ENV =

MKDIR = mkdir -p $(dir $@)
MKDIR_TARGET = mkdir -p $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR) $(LIB_DIR)

RUN_TESTS = for t in $(TEST_BINS); do echo === $$t ===; ./$$t || exit 1; done; echo All tests passed!
