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

# Debug build with additional debugging symbols
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

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
	@echo "  all         - Build the main executable (default)"
	@echo "  debug       - Build with debugging symbols"
	@echo "  performance - Build with maximum optimization"
	@echo "  static      - Build static executable"
	@echo "  install     - Install to /usr/local/bin (requires sudo)"
	@echo "  uninstall   - Remove from /usr/local/bin (requires sudo)"
	@echo "  clean       - Remove build artifacts"
	@echo "  check-deps  - Check for required dependencies"
	@echo "  test        - Run basic functionality tests"
	@echo "  benchmark   - Show benchmark instructions"
	@echo "  info        - Show build information"
	@echo "  help        - Show this help message"

.PHONY: all debug performance static install uninstall clean check-deps test benchmark info help