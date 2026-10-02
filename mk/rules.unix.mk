# Unix (Linux / macOS) rules.

BUILD_DIR = build/unix
EXE =
SO_EXT = .so
AR = ar
LDFLAGS = -lrt -lm
SO_LDFLAGS =
TEST_RUN_ENV = LD_LIBRARY_PATH=$(LIB_DIR)

MKDIR = mkdir -p $(dir $@)
MKDIR_TARGET = mkdir -p $@


clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR) $(LIB_DIR)

RUN_TESTS = for t in $(TEST_BINS); do echo === $$t ===; $(TEST_RUN_ENV) ./$$t || exit 1; done; echo All tests passed!
