SOURCE_DIR := src
SOURCES    := $(shell find $(SOURCE_DIR) -name "*.c")
OBJECTS    := $(SOURCES:.c=.o)
LINUX_INCLUDE ?= ../linux/usr/include

# Tools
CC              := gcc
AR              := ar
CFLAGS          := -g -Wall -Werror -O0 -Iinclude -I$(LINUX_INCLUDE)

# Rules
.PHONY: all clean

all: libsev-guest-get-report.a

libsev-guest-get-report.a: $(SOURCE_DIR)/get-report.o
	$(AR) cr -o $@ $^

clean:
	$(RM) libsev-guest-get-report.a $(OBJECTS) 
