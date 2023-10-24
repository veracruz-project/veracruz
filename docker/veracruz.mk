SOURCE_DIR := src
SOURCES    := $(shell find $(SOURCE_DIR) -name "*.c")
OBJECTS    := $(SOURCES:.c=.o)
LINUX_INCLUDE ?= ../linux/guest/usr/include

# Tools
CC              := gcc
#CC              := musl-gcc
AR              := ar
CFLAGS          := -g -O0 -Iinclude -I$(LINUX_INCLUDE)

# Rules
.PHONY: all clean

all: libsev-guest-get-report.a

libsev-guest-get-report.a: $(SOURCE_DIR)/get-report.o
	$(AR) cr -o $@ $^
	#strip -s --keep-symbol get_report --keep-symbol test --keep-symbol get_extended_report libsev-guest-get-report.a
	#strip  --remove-relocations=* -N main libsev-guest-get-report.a
	#ranlib libsev-guest-get-report.a

clean:
	$(RM) libsev-guest-get-report.a $(OBJECTS) 
