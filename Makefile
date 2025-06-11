# Variables
CC = gcc
CFLAGS = -Wall -g -std=c99 # Added -std=c99 for uintptr_t and other modern C features
LDFLAGS =

# Target executable name
TARGET = chain_finder

# Default target (builds the executable)
all: $(TARGET)

# Rule to build the target executable
$(TARGET): chain_finder.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) chain_finder.c

# Clean target (removes the executable and any potential object files)
clean:
	rm -f $(TARGET) *.o

# Phony targets (targets that don't represent actual files)
.PHONY: all clean
