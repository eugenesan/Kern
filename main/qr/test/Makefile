CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -Wno-unused-function -Wno-unused-parameter -std=gnu11 -g
ROOT := ../../..
UR_DIR := $(ROOT)/components/cUR
# cUR is an upstream component whose own Makefile writes into its source
# tree.  Build it under this directory instead; override UR_BUILD to keep
# the objects somewhere else (the kern-nexus scripts use /tmp).
UR_BUILD ?= $(UR_DIR)/build
UR_LIB := $(UR_BUILD)/libur.a
INCLUDES := -I.. -I$(ROOT)/main -I$(ROOT)/components/bbqr/src \
	-I$(ROOT)/components/deflate_codec/src -I$(UR_DIR)/src
SOURCES := test_parser.c ../parser.c \
	$(ROOT)/components/bbqr/src/bbqr.c \
	$(ROOT)/components/bbqr/src/base32.c \
	$(ROOT)/components/deflate_codec/src/deflate_codec.c
TARGET := test_parser
PROGRESS_TARGET := test_progress
YUV420_TARGET := test_yuv420
FRAME_POOL_TARGET := test_frame_pool
SIM_STUBS := $(ROOT)/simulator/platform/esp_idf_stubs
# Wrapped so the tests can force an allocation failure on demand.
LDFLAGS := -Wl,--wrap=malloc

all: $(TARGET) $(PROGRESS_TARGET) $(YUV420_TARGET) $(FRAME_POOL_TARGET)

$(UR_LIB): $(shell find $(UR_DIR)/src -name '*.[ch]' 2>/dev/null)
	@mkdir -p $(UR_BUILD)
	$(MAKE) -C $(UR_DIR) OBJDIR=$(UR_BUILD)/obj TARGET=$(UR_LIB) all

$(TARGET): $(SOURCES) ../parser.h ../../utils/attributes.h \
	$(ROOT)/components/bbqr/src/bbqr.h $(ROOT)/components/bbqr/src/base32.h \
	$(ROOT)/components/deflate_codec/src/deflate_codec.h $(UR_LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SOURCES) $(UR_LIB) $(LDFLAGS) -lz -lm

$(PROGRESS_TARGET): test_progress.c ../progress.h ../parser.h ../../utils/attributes.h \
	$(SIM_STUBS)/freertos_sim.c $(shell find $(SIM_STUBS)/include -name '*.h')
	$(CC) $(CFLAGS) -I$(SIM_STUBS)/include -o $@ test_progress.c $(SIM_STUBS)/freertos_sim.c -pthread

$(YUV420_TARGET): test_yuv420.c ../yuv420.h
	$(CC) $(CFLAGS) -o $@ test_yuv420.c

$(FRAME_POOL_TARGET): test_frame_pool.c ../frame_pool.h
	$(CC) $(CFLAGS) -o $@ test_frame_pool.c

run: $(TARGET) $(PROGRESS_TARGET) $(YUV420_TARGET) $(FRAME_POOL_TARGET)
	./$(TARGET)
	./$(PROGRESS_TARGET)
	./$(YUV420_TARGET)
	./$(FRAME_POOL_TARGET)

clean:
	rm -f $(TARGET) $(PROGRESS_TARGET) $(YUV420_TARGET) $(FRAME_POOL_TARGET)

.PHONY: all run clean
