# Makefile for HTTPd Log Analyzer (C Implementation)
# High-performance log analysis tool

CC = gcc
CFLAGS = -O3 -Wall -Wextra -std=c99 -pthread
LDFLAGS = -lcurl -lpthread
TARGET = httpd-log-analyzer
SOURCE = httpd-log-analyzer.c

# Default target
all: $(TARGET)

# Build the main executable
$(TARGET): $(SOURCE)
	@echo "Building high-performance HTTPd Log Analyzer..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)
	@echo "Build complete! Executable: $(TARGET)"
	@echo ""
	@echo "Usage: ./$(TARGET) [options] <logfile>"
	@echo "Options:"
	@echo "  --enable-geo      Enable geographic IP lookup"
	@echo "  --detailed-mode   Enable comprehensive attack detection"
	@echo "  --debug           Enable debug output"
	@echo "  --verbose         Enable verbose processing information"
	@echo ""

# Debug build with additional debugging symbols and sanitizers (if supported)
debug: CFLAGS += -g -DDEBUG -fno-omit-frame-pointer
debug: LDFLAGS += $(shell $(CC) -fsanitize=address -E - < /dev/null > /dev/null 2>&1 && echo "-fsanitize=address -fsanitize=undefined" || echo "")
debug: $(TARGET)

# Force debug build with sanitizers (requires GCC 4.8+ or Clang 3.1+)
debug-sanitizer: CFLAGS += -g -DDEBUG -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer
debug-sanitizer: LDFLAGS += -fsanitize=address -fsanitize=undefined
debug-sanitizer: $(TARGET)

# Memory debugging build with Valgrind compatibility
memcheck: CFLAGS += -g -O0 -DDEBUG -fno-omit-frame-pointer
memcheck: $(TARGET)

# Performance optimized build
performance: CFLAGS += -march=native -mtune=native -flto
performance: $(TARGET)

# Static build (for distribution)
static: LDFLAGS += -static
static: $(TARGET)

# Install to system (requires sudo)
install: $(TARGET)
	@echo "Installing $(TARGET) to /usr/local/bin/"
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(TARGET)
	@echo "Installation complete!"

# Uninstall from system
uninstall:
	@echo "Removing $(TARGET) from /usr/local/bin/"
	sudo rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstallation complete!"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(TARGET)
	@echo "Clean complete!"

# Check dependencies
check-deps:
	@echo "Checking dependencies..."
	@which gcc > /dev/null || (echo "ERROR: gcc not found. Install with: sudo apt-get install gcc" && exit 1)
	@pkg-config --exists libcurl || (echo "ERROR: libcurl not found. Install with: sudo apt-get install libcurl4-openssl-dev" && exit 1)
	@echo "GCC version: $$(gcc --version | head -1)"
	@echo "Checking sanitizer support..."
	@$(CC) -fsanitize=address -E - < /dev/null > /dev/null 2>&1 && echo "AddressSanitizer: SUPPORTED" || echo "AddressSanitizer: NOT SUPPORTED (use 'make debug' instead of 'make debug-sanitizer')"
	@echo "All dependencies satisfied!"

# Run basic tests
test: $(TARGET)
	@echo "Running basic functionality tests..."
	@echo "Test 1: Help message"
	./$(TARGET) --help
	@echo ""
	@echo "Test 2: Version and build info"
	@echo "Built with: $(CC) $(CFLAGS)"
	@echo "Linked with: $(LDFLAGS)"
	@echo ""
	@echo "To test with actual log files, run:"
	@echo "  ./$(TARGET) /var/log/apache2/access.log"
	@echo "  ./$(TARGET) --verbose --enable-geo /var/log/nginx/access.log"

# Debug test with core dump analysis
debug-test: debug
	@echo "Running debug tests with sanitizers..."
	@echo "This will help identify memory issues and crashes"
	@echo "Usage: make debug-test TESTFILE=your_log_file.txt"
	@if [ -n "$(TESTFILE)" ]; then \
		echo "Testing with file: $(TESTFILE)"; \
		./$(TARGET) --debug --verbose $(TESTFILE); \
	else \
		echo "No test file specified. Use: make debug-test TESTFILE=logfile.txt"; \
	fi

# Valgrind memory check
valgrind-test: memcheck
	@echo "Running Valgrind memory check..."
	@echo "Usage: make valgrind-test TESTFILE=your_log_file.txt"
	@if [ -n "$(TESTFILE)" ]; then \
		echo "Testing with file: $(TESTFILE)"; \
		valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TARGET) --debug $(TESTFILE); \
	else \
		echo "No test file specified. Use: make valgrind-test TESTFILE=logfile.txt"; \
	fi

# Performance benchmark (requires test log file)
benchmark: $(TARGET)
	@echo "Performance benchmark requires a test log file."
	@echo "Create a test file or use an existing log file:"
	@echo "  time ./$(TARGET) --verbose large_logfile.log"
	@echo "  time ./$(TARGET) --detailed-mode --enable-geo large_logfile.log"

# Show build information
info:
	@echo "HTTPd Log Analyzer (C Implementation)"
	@echo "======================================"
	@echo "Compiler: $(CC)"
	@echo "Flags: $(CFLAGS)"
	@echo "Libraries: $(LDFLAGS)"
	@echo "Target: $(TARGET)"
	@echo "Source: $(SOURCE)"
	@echo ""
	@echo "Expected performance improvement: 5-15x over shell script"
	@echo "Features:"
	@echo "  - Multi-threaded processing"
	@echo "  - Memory-efficient chunk processing"
	@echo "  - Optimized pattern matching"
	@echo "  - Geographic IP lookup (optional)"
	@echo "  - Comprehensive attack detection"

# Help target
help:
	@echo "Available targets:"
	@echo "  all           - Build the main executable (default)"
	@echo "  debug         - Build with debugging symbols (auto-detect sanitizers)"
	@echo "  debug-sanitizer - Build with sanitizers (requires GCC 4.8+)"
	@echo "  memcheck      - Build for Valgrind memory checking"
	@echo "  performance   - Build with maximum optimization"
	@echo "  static        - Build static executable"
	@echo "  install       - Install to /usr/local/bin (requires sudo)"
	@echo "  uninstall     - Remove from /usr/local/bin (requires sudo)"
	@echo "  clean         - Remove build artifacts"
	@echo "  check-deps    - Check for required dependencies"
	@echo "  test          - Run basic functionality tests"
	@echo "  debug-test    - Run debug tests with sanitizers"
	@echo "  valgrind-test - Run Valgrind memory check"
	@echo "  benchmark     - Show benchmark instructions"
	@echo "  info          - Show build information"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "Debug usage examples:"
	@echo "  make debug-test TESTFILE=ssl_request_log-20250810.txt"
	@echo "  make valgrind-test TESTFILE=access_log-20250810.txt"

.PHONY: all debug debug-sanitizer memcheck performance static install uninstall clean check-deps test debug-test valgrind-test benchmark info help