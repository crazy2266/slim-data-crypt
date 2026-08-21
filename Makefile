CC = gcc
CFLAGS = -Wall -Wextra -O3 -g -Iinclude -std=c99
LDFLAGS = -lrt -lm

SRC_DIR = src
TEST_DIR = tests
BUILD_DIR = build
BIN_DIR = bin

SRCS = $(wildcard $(SRC_DIR)/*.c) \
       $(wildcard $(SRC_DIR)/**/*.c)

TEST_SRCS = $(wildcard $(TEST_DIR)/test_*.c)
TEST_BINS = $(patsubst $(TEST_DIR)/%.c,$(BIN_DIR)/%.out,$(TEST_SRCS))

OBJS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS))

all: $(BIN_DIR) $(TEST_BINS)

$(BIN_DIR) $(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/%.out: $(TEST_DIR)/%.c $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(OBJS) $(LDFLAGS)

test-%: $(BIN_DIR)/%.out
	@echo "=== Running $* ==="
	@./$(BIN_DIR)/$*.out

test: $(TEST_BINS)
	@echo ""
	@echo "========================================"
	@echo "Running all tests..."
	@echo "========================================"
	@for test in $(TEST_BINS); do \
		echo ""; \
		echo "=== $$(basename $$test .out) ==="; \
		./$$test || exit 1; \
	done
	@echo ""
	@echo "========================================"
	@echo "All tests passed!"
	@echo "========================================"

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

distclean: clean
	rm -rf *.o *.exe

list:
	@echo "Available tests:"
	@for test in $(TEST_BINS); do \
		echo "  $$(basename $$test)"; \
	done

.PHONY: all clean distclean test list
