# slim-data-crypt top-level Makefile
#
# Detects the host platform and includes the matching rule set from mk/.
#   Windows (MSYS2/MinGW): mk/rules.windows.mk
#   Unix (Linux/macOS):    mk/rules.unix.mk

ifeq ($(OS),Windows_NT)
  PLATFORM := windows
else
  PLATFORM := unix
endif

.DEFAULT_GOAL := all

CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -Iinclude -std=c99

SRC_DIR = src
TEST_DIR = tests
BIN_DIR = bin
# BUILD_DIR is defined per-platform in mk/rules.*.mk (build-win / build-unix)

# Source discovery: nested wildcards, up to 7 directory levels.
SRCS = $(wildcard $(SRC_DIR)/*.c) \
       $(wildcard $(SRC_DIR)/*/*.c) \
       $(wildcard $(SRC_DIR)/*/*/*.c) \
       $(wildcard $(SRC_DIR)/*/*/*/*.c) \
       $(wildcard $(SRC_DIR)/*/*/*/*/*.c) \
       $(wildcard $(SRC_DIR)/*/*/*/*/*/*.c) \
       $(wildcard $(SRC_DIR)/*/*/*/*/*/*/*.c)

TEST_SRCS = $(wildcard $(TEST_DIR)/test_*.c)

# platform-specific variables and rules
include mk/rules.$(PLATFORM).mk

# derived variables (need BUILD_DIR/EXE from the platform file)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
TEST_BINS = $(patsubst $(TEST_DIR)/%.c,$(BIN_DIR)/%$(EXE),$(TEST_SRCS))

all: $(BIN_DIR) $(BUILD_DIR) $(TEST_BINS)

$(BIN_DIR) $(BUILD_DIR):
	$(MKDIR_TARGET)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(MKDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/%$(EXE): $(TEST_DIR)/%.c $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(OBJS) $(LDFLAGS)

test: $(TEST_BINS)
	$(RUN_TESTS)

.PHONY: all test clean
