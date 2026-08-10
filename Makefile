CC = gcc
CFLAGS = -Wall -Wextra -O3 -g -Iinclude
LDFLAGS = -lm

SRC_DIR = src
TEST_DIR = tests
BUILD_DIR = build
BIN_DIR = bin

# 自动收集所有 .c 源文件（排除测试文件）
SRCS = $(wildcard $(SRC_DIR)/*.c) \
       $(wildcard $(SRC_DIR)/**/*.c)

# 自动收集所有测试文件
TEST_SRCS = $(wildcard $(TEST_DIR)/test_*.c)
TEST_BINS = $(patsubst $(TEST_DIR)/%.c,$(BIN_DIR)/%,$(TEST_SRCS))

# 生成对象文件列表
OBJS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS))

# 默认目标
all: $(BIN_DIR) $(TEST_BINS)

# 创建必要的目录
$(BIN_DIR) $(BUILD_DIR):
	mkdir -p $@

# 编译源文件到对象文件
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# 链接测试程序
$(BIN_DIR)/%: $(TEST_DIR)/%.c $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(OBJS) $(LDFLAGS)

# 运行单个测试
test-%: $(BIN_DIR)/%
	@echo "=== Running $* ==="
	@./$(BIN_DIR)/$*

# 运行所有测试
test: $(TEST_BINS)
	@echo ""
	@echo "========================================"
	@echo "Running all tests..."
	@echo "========================================"
	@for test in $(TEST_BINS); do \
		echo ""; \
		echo "=== $$(basename $$test) ==="; \
		./$$test || exit 1; \
	done
	@echo ""
	@echo "========================================"
	@echo "All tests passed!"
	@echo "========================================"

# 清理
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# 深度清理
distclean: clean
	rm -rf *.o *.exe

# 打印测试列表
list:
	@echo "Available tests:"
	@for test in $(TEST_BINS); do \
		echo "  $$(basename $$test)"; \
	done

.PHONY: all clean distclean test list
