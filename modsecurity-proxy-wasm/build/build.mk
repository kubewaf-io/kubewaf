# Build logic for modsecurity-proxy-wasm (used locally and inside the Docker builder).
# Dependency pins: Makefile (Renovate-managed *_VERSION / *_SHA variables).

SHELL := /bin/bash

BUILD_DIR       ?= $(abspath .)
PREFIX          ?= $(BUILD_DIR)/.cache/deps
JOBS            ?= $(shell nproc 2>/dev/null || echo 4)

EMSDK           ?= $(PREFIX)/emsdk

PROXY_WASM_CPP_SDK ?= $(PREFIX)/proxy-wasm-cpp-sdk
PCRE2_SRC       ?= $(PREFIX)/pcre2-wasm
PCRE2_EM        ?= $(PREFIX)/pcre2-em
MODSEC_SRC      ?= $(PREFIX)/modsec
MODSECURITY_LIB ?= $(PREFIX)/modsecurity-lib
CRS_DIR         ?= $(PREFIX)/crs

MODSECURITY_PROXY_WASM_OUT ?= $(BUILD_DIR)/dist/modsecurity-proxy-wasm.wasm
MODSECURITY_PROXY_WAT_OUT  ?= $(BUILD_DIR)/dist/modsecurity-proxy-wasm.wat

STAMPS_DIR      := $(BUILD_DIR)/.cache/stamps
OBJ_DIR         := $(BUILD_DIR)/.cache/obj
WASM_GETENTROPY_OBJ := $(OBJ_DIR)/wasm_getentropy.o
WASM_STUBS_OBJ      := $(OBJ_DIR)/wasm_stubs.o

BUILD_RULES_DIR    := $(BUILD_DIR)/build/rules
BUILD_SCRIPTS_DIR  := $(BUILD_DIR)/build/scripts

GENERATED_CC    := $(BUILD_DIR)/src/generated/rules_catalog.cc
GENERATED_H     := $(BUILD_DIR)/src/generated/rules_catalog.h

PCRE2_PKG_VERSION := $(patsubst pcre2-%,%,$(PCRE2_VERSION))

EMS_ENV         := EMSDK=$(EMSDK) . $(EMSDK)/emsdk_env.sh &&

MODSEC_CONFIGURE_FLAGS := \
	--with-pcre2=$(PCRE2_EM) \
	--without-yajl --without-geoip --without-libxml --without-curl \
	--without-lua --disable-shared --disable-examples --disable-libtool-lock \
	--disable-debug-logs --disable-mutex-on-pm --without-lmdb --without-maxmind \
	--without-ssdeep

EMSCRIPTEN_LINK_OPTS := --no-entry \
	-sSTANDALONE_WASM -sEXPORTED_FUNCTIONS=_malloc -sFILESYSTEM=1 \
	-sALLOW_MEMORY_GROWTH=1 -sINITIAL_MEMORY=16MB -sSTACK_SIZE=1MB

PLUGIN_SRCS := \
	$(BUILD_DIR)/src/modsecurity_proxy_wasm.cc \
	$(BUILD_DIR)/src/metrics.cc \
	$(BUILD_DIR)/src/waf_config.cc \
	$(BUILD_DIR)/src/wasm_vfs.cc \
	$(GENERATED_CC)

.PHONY: all build deps clean-build modsecurity-proxy-wasm.wasm modsecurity-proxy-wasm.wat

all: modsecurity-proxy-wasm.wasm modsecurity-proxy-wasm.wat
build: all

modsecurity-proxy-wasm.wasm: $(MODSECURITY_PROXY_WASM_OUT)
modsecurity-proxy-wasm.wat: $(MODSECURITY_PROXY_WAT_OUT)

deps: $(STAMPS_DIR)/emsdk \
	$(STAMPS_DIR)/proxy-wasm-cpp-sdk \
	$(STAMPS_DIR)/pcre2 \
	$(STAMPS_DIR)/modsecurity \
	$(STAMPS_DIR)/crs

$(STAMPS_DIR)/emsdk:
	@mkdir -p $(STAMPS_DIR) $(PREFIX)
	rm -rf $(EMSDK)
	git clone --depth 1 https://github.com/emscripten-core/emsdk.git $(EMSDK)
	cd $(EMSDK) && ./emsdk install $(EMSDK_VERSION) --shallow && ./emsdk activate $(EMSDK_VERSION)
	touch $@

$(STAMPS_DIR)/proxy-wasm-cpp-sdk: | $(STAMPS_DIR)/emsdk
	@mkdir -p $(STAMPS_DIR) $(PREFIX)
	rm -rf $(PROXY_WASM_CPP_SDK)
	git clone https://github.com/proxy-wasm/proxy-wasm-cpp-sdk.git $(PROXY_WASM_CPP_SDK)
	cd $(PROXY_WASM_CPP_SDK) && git checkout $(PROXY_WASM_CPP_SDK_VERSION)
	test "$$(git -C $(PROXY_WASM_CPP_SDK) rev-parse HEAD)" = "$(PROXY_WASM_CPP_SDK_VERSION)"
	python3 $(BUILD_SCRIPTS_DIR)/patch-sdk-getentropy.py $(PROXY_WASM_CPP_SDK)/proxy_wasm_intrinsics.cc
	touch $@

$(STAMPS_DIR)/pcre2: | $(STAMPS_DIR)/emsdk
	@mkdir -p $(STAMPS_DIR) $(PREFIX)
	rm -rf $(PCRE2_SRC)
	git clone --branch "$(PCRE2_VERSION)" https://github.com/PCRE2Project/pcre2.git $(PCRE2_SRC)
	test "$$(git -C $(PCRE2_SRC) rev-parse HEAD)" = "$(PCRE2_SHA)"
	cd $(PCRE2_SRC) && autoreconf -ivf
	cd $(PCRE2_SRC) && $(EMS_ENV) emconfigure ./configure --host wasm32 \
		--disable-dependency-tracking \
		--enable-utf8 \
		--enable-pcre2-8 \
		--enable-pcre2-16 \
		--enable-pcre2-32 \
		--enable-unicode-properties \
		--disable-shared \
		--disable-cpp
	cd $(PCRE2_SRC) && $(EMS_ENV) emmake make
	mkdir -p $(PCRE2_SRC)/targets/wasm32-emscripten
	cp $(PCRE2_SRC)/.libs/*.a $(PCRE2_SRC)/targets/wasm32-emscripten/
	mkdir -p $(PCRE2_EM)/include $(PCRE2_EM)/lib/pkgconfig
	cp $(PCRE2_SRC)/src/pcre2.h $(PCRE2_EM)/include/
	cp $(PCRE2_SRC)/targets/wasm32-emscripten/libpcre2-8.a $(PCRE2_EM)/lib/
	printf '%s\n' \
		'prefix=$(PCRE2_EM)' \
		'exec_prefix=$${prefix}' \
		'libdir=$${exec_prefix}/lib' \
		'includedir=$${prefix}/include' \
		'Name: libpcre2-8' \
		'Description: Perl Compatible Regular Expressions (2)' \
		'Version: $(PCRE2_PKG_VERSION)' \
		'Libs: -L$${libdir} -lpcre2-8' \
		'Cflags: -I$${includedir}' \
		> $(PCRE2_EM)/lib/pkgconfig/libpcre2-8.pc
	touch $@

$(STAMPS_DIR)/modsecurity: $(STAMPS_DIR)/pcre2 \
		$(BUILD_DIR)/build/patches/modsecurity-pm-from-file-catalog.patch
	@mkdir -p $(STAMPS_DIR) $(PREFIX)
	rm -rf $(MODSEC_SRC)
	git clone https://github.com/owasp-modsecurity/ModSecurity.git $(MODSEC_SRC)
	cd $(MODSEC_SRC) && git checkout $(MODSECURITY_SHA)
	test "$$(git -C $(MODSEC_SRC) rev-parse HEAD)" = "$(MODSECURITY_SHA)"
	cd $(MODSEC_SRC) && git submodule update --init --recursive
	# Serve CRS .data phrase lists from the proxy-wasm catalog (Envoy V8 has no MEMFS).
	cd $(MODSEC_SRC) && patch -p1 < $(BUILD_DIR)/build/patches/modsecurity-pm-from-file-catalog.patch
	cd $(MODSEC_SRC) && ./build.sh
	cd $(MODSEC_SRC) && $(EMS_ENV) PKG_CONFIG_PATH=$(PCRE2_EM)/lib/pkgconfig \
		emconfigure ./configure $(MODSEC_CONFIGURE_FLAGS)
	cd $(MODSEC_SRC) && $(EMS_ENV) emmake make -j$(JOBS) -C others
	cd $(MODSEC_SRC) && $(EMS_ENV) emmake make -j$(JOBS) -C src libmodsecurity.la
	mkdir -p $(MODSECURITY_LIB)/lib $(MODSECURITY_LIB)/include
	cp $(MODSEC_SRC)/src/.libs/libmodsecurity.a $(MODSECURITY_LIB)/lib/
	cp -r $(MODSEC_SRC)/headers/* $(MODSECURITY_LIB)/include/
	touch $@

$(STAMPS_DIR)/crs:
	@mkdir -p $(STAMPS_DIR) $(PREFIX)
	rm -rf $(CRS_DIR)
	git clone --depth 1 --branch "$(CRS_VERSION)" https://github.com/coreruleset/coreruleset.git $(CRS_DIR)
	touch $@

$(GENERATED_CC) $(GENERATED_H): $(STAMPS_DIR)/crs \
		$(BUILD_RULES_DIR)/demo-conf.conf \
		$(BUILD_RULES_DIR)/ftw-config.conf \
		$(BUILD_RULES_DIR)/kubewaf-defaults.conf \
		$(BUILD_SCRIPTS_DIR)/generate_rules_catalog.py
	@mkdir -p $(BUILD_DIR)/src/generated
	python3 $(BUILD_SCRIPTS_DIR)/generate_rules_catalog.py \
		--crs $(CRS_DIR) \
		--demo $(BUILD_RULES_DIR)/demo-conf.conf \
		--ftw $(BUILD_RULES_DIR)/ftw-config.conf \
		--kubewaf-defaults $(BUILD_RULES_DIR)/kubewaf-defaults.conf \
		--out-cc $(GENERATED_CC) \
		--out-h $(GENERATED_H)

$(WASM_GETENTROPY_OBJ): $(BUILD_DIR)/src/wasm_getentropy.c | $(STAMPS_DIR)/emsdk
	@mkdir -p $(OBJ_DIR)
	$(EMS_ENV) emcc -c $(BUILD_DIR)/src/wasm_getentropy.c -o $(WASM_GETENTROPY_OBJ)

$(WASM_STUBS_OBJ): $(BUILD_DIR)/src/wasm_stubs.c | $(STAMPS_DIR)/emsdk
	@mkdir -p $(OBJ_DIR)
	$(EMS_ENV) emcc -c $(BUILD_DIR)/src/wasm_stubs.c -o $(WASM_STUBS_OBJ)

$(MODSECURITY_PROXY_WASM_OUT): deps $(GENERATED_CC) $(WASM_GETENTROPY_OBJ) $(WASM_STUBS_OBJ) $(PLUGIN_SRCS) \
		$(BUILD_DIR)/src/waf_config.h $(STAMPS_DIR)/proxy-wasm-cpp-sdk
	@mkdir -p $(dir $(MODSECURITY_PROXY_WASM_OUT))
	$(EMS_ENV) em++ --std=c++17 -O3 -flto \
		$(EMSCRIPTEN_LINK_OPTS) \
		--js-library $(PROXY_WASM_CPP_SDK)/proxy_wasm_intrinsics.js \
		-I$(BUILD_DIR)/src \
		-I$(PROXY_WASM_CPP_SDK) \
		-I$(MODSECURITY_LIB)/include \
		-I$(PCRE2_EM)/include \
		$(PROXY_WASM_CPP_SDK)/proxy_wasm_intrinsics.cc \
		$(BUILD_DIR)/src/modsecurity_proxy_wasm.cc \
		$(BUILD_DIR)/src/metrics.cc \
		$(BUILD_DIR)/src/waf_config.cc \
		$(BUILD_DIR)/src/wasm_vfs.cc \
		$(GENERATED_CC) \
		$(MODSECURITY_LIB)/lib/libmodsecurity.a \
		$(WASM_GETENTROPY_OBJ) \
		$(WASM_STUBS_OBJ) \
		$(PCRE2_EM)/lib/libpcre2-8.a \
		-o $(MODSECURITY_PROXY_WASM_OUT)

$(MODSECURITY_PROXY_WAT_OUT): $(MODSECURITY_PROXY_WASM_OUT)
	@mkdir -p $(dir $(MODSECURITY_PROXY_WAT_OUT))
	$(EMS_ENV) wasm2wat $(MODSECURITY_PROXY_WASM_OUT) -o $(MODSECURITY_PROXY_WAT_OUT) || touch $(MODSECURITY_PROXY_WAT_OUT)

clean-build:
	rm -rf $(STAMPS_DIR) $(OBJ_DIR) $(BUILD_DIR)/src/generated $(BUILD_DIR)/dist $(BUILD_DIR)/.cache