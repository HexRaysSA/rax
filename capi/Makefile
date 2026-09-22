# ============================================================================
# RAX C/C++ API — convenience Makefile
#
#   make            build the release library (librax) via cargo
#   make debug      build the debug library
#   make test       build, then compile & run the C/C++ examples
#   make install    install headers, libraries, and pkg-config (PREFIX=/usr/local)
#   make clean      remove built example binaries
#
# The cargo workspace places artifacts in ../target/{release,debug}.
# ============================================================================

PREFIX      ?= /usr/local
CARGO       ?= cargo
CC          ?= cc
CXX         ?= c++
PROFILE     ?= release

HERE        := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
TARGET_DIR  ?= $(HERE)../target
INCDIR      := $(HERE)include
PKG_VERSION := $(shell sed -n 's/^\#define RAX_API_[A-Z]* \([0-9]*\)u/\1/p' "$(INCDIR)/rax.h" | paste -sd. -)
EXAMPLE_DIR := $(HERE)examples
TEST_DIR    := $(HERE)tests

ifeq ($(PROFILE),release)
  CARGO_FLAGS := --release
  OUT_DIR     := $(TARGET_DIR)/release
else
  CARGO_FLAGS :=
  OUT_DIR     := $(TARGET_DIR)/debug
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  DYLIB_EXT     := dylib
  LDPATH_VAR    := DYLD_LIBRARY_PATH
  RPATH_FLAG    := -Wl,-rpath,$(OUT_DIR)
  PRIVATE_LIBS  := -framework CoreFoundation -framework Security \
                   -framework SystemConfiguration -liconv -lobjc -lpthread
else
  DYLIB_EXT     := so
  LDPATH_VAR    := LD_LIBRARY_PATH
  RPATH_FLAG    := -Wl,-rpath,$(OUT_DIR)
  PRIVATE_LIBS  := -lpthread -ldl -lm -lrt -lutil
endif

DYLIB       := $(OUT_DIR)/librax.$(DYLIB_EXT)
STATICLIB   := $(OUT_DIR)/librax.a

C_SRCS      := $(wildcard $(EXAMPLE_DIR)/*.c)
CXX_SRCS    := $(wildcard $(EXAMPLE_DIR)/*.cpp)
C_BINS      := $(patsubst $(EXAMPLE_DIR)/%.c,$(EXAMPLE_DIR)/%,$(C_SRCS))
CXX_BINS    := $(patsubst $(EXAMPLE_DIR)/%.cpp,$(EXAMPLE_DIR)/%,$(CXX_SRCS))
ABI_TEST_OBJ := $(TEST_DIR)/analyze_abi.o $(TEST_DIR)/fault_abi.o

CFLAGS      ?= -O2 -Wall -Wextra
CXXFLAGS    ?= -O2 -Wall -Wextra -std=c++17

.PHONY: all release debug lib test examples abi-test clean install

all: release

release:
	$(CARGO) build --locked --package rax-capi --release

debug:
	$(CARGO) build --locked --package rax-capi

lib:
	$(CARGO) build --locked --package rax-capi $(CARGO_FLAGS)

# Build the library, compile all examples against the dynamic lib, run them.
test: lib abi-test examples
	@status=0; \
	for bin in $(C_BINS) $(CXX_BINS); do \
	  echo "== running $$bin =="; \
	  $(LDPATH_VAR)=$(OUT_DIR) $$bin || status=$$?; \
	done; \
	exit $$status

examples: $(C_BINS) $(CXX_BINS)

abi-test: $(ABI_TEST_OBJ)

$(TEST_DIR)/%.o: $(TEST_DIR)/%.c $(INCDIR)/rax.h
	$(CC) -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Werror \
	      -I$(INCDIR) -c $< -o $@

$(EXAMPLE_DIR)/%: $(EXAMPLE_DIR)/%.c lib
	$(CC) $(CFLAGS) -I$(INCDIR) $< -L$(OUT_DIR) -lrax $(RPATH_FLAG) -o $@

$(EXAMPLE_DIR)/%: $(EXAMPLE_DIR)/%.cpp lib
	$(CXX) $(CXXFLAGS) -I$(INCDIR) $< -L$(OUT_DIR) -lrax $(RPATH_FLAG) -o $@

install: lib
	@install -d "$(PREFIX)/include" "$(PREFIX)/lib" "$(PREFIX)/lib/pkgconfig"
	install -m 0644 "$(INCDIR)/rax.h" "$(PREFIX)/include/rax.h"
	@[ -f "$(INCDIR)/rax.hpp" ] && install -m 0644 "$(INCDIR)/rax.hpp" "$(PREFIX)/include/rax.hpp" || true
	@[ -f "$(DYLIB)" ] && install -m 0755 "$(DYLIB)" "$(PREFIX)/lib/" || true
	@[ -f "$(STATICLIB)" ] && install -m 0644 "$(STATICLIB)" "$(PREFIX)/lib/" || true
	@sed -e 's#@PKG_PREFIX@#$${pcfiledir}/../..#g' \
	     -e 's#@PKG_LIBDIR@#$${prefix}/lib#g' \
	     -e 's#@PKG_INCLUDEDIR@#$${prefix}/include#g' \
	     -e 's#@PKG_VERSION@#$(PKG_VERSION)#g' \
	     -e 's#@PKG_PRIVATE_LIBS@#$(PRIVATE_LIBS)#g' \
	     "$(HERE)rax.pc.in" > "$(PREFIX)/lib/pkgconfig/rax.pc"
	@echo "installed rax to $(PREFIX)"

clean:
	rm -f $(C_BINS) $(CXX_BINS) $(ABI_TEST_OBJ)
