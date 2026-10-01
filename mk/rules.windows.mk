# Windows (MSYS2 / MinGW) rules.

BUILD_DIR = build/win
EXE = .exe
LDFLAGS = -lm -lbcrypt

# mkdir helper: ensure directory exists
MKDIR = if not exist $(subst /,\,$(dir $@)) mkdir $(subst /,\,$(dir $@))
# create a top-level directory (for order-only prerequisites)
MKDIR_TARGET = if not exist $(subst /,\,$@) mkdir $(subst /,\,$@)

clean:
	if exist $(BUILD_DIR) rmdir /s /q $(BUILD_DIR)
	if exist $(BIN_DIR) rmdir /s /q $(BIN_DIR)

RUN_TESTS = $(foreach t,$(TEST_BINS),echo === $(notdir $t) === && $(subst /,\,$t) &&) echo All tests passed!
