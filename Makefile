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
CFLAGS = -Wall -Wextra -O2 -g -Iinclude -std=c99 -MMD -MP -fPIC

SRC_DIR = src
TEST_DIR = tests
BIN_DIR = bin
LIB_DIR = lib
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

LIB_A  = $(LIB_DIR)/libsdcrypt.a
LIB_SO = $(LIB_DIR)/libsdcrypt$(SO_EXT)

# Tests link against the static library; both static and shared
# libraries are always built (like OpenSSL).
TEST_LIB = $(LIB_A)

# Auto-generated header dependencies (-MMD -MP).  The leading '-' makes a
# missing .d file (first build) a non-error.
-include $(OBJS:.o=.d)

all: libs tests

# ---- library ----

libs: $(LIB_A) $(LIB_SO)

$(LIB_A): $(OBJS) | $(LIB_DIR)
	$(AR) rcs $@ $^

$(LIB_SO): $(OBJS) | $(LIB_DIR)
	$(CC) -shared -o $@ $^ $(SO_LDFLAGS) $(LDFLAGS)

$(BIN_DIR) $(BUILD_DIR) $(LIB_DIR):
	$(MKDIR_TARGET)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(MKDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# ---- tests (link against the static library) ----

$(BIN_DIR)/%$(EXE): $(TEST_DIR)/%.c $(LIB_A) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_A) $(LDFLAGS)

test: $(TEST_BINS)
	$(RUN_TESTS)

.PHONY: all libs test clean
