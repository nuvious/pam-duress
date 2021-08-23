BIN_DIR := bin
OBJ_DIR := obj
SRC_DIR := src
CC := gcc
CPP := g++
CFLAGS := -fPIC -fno-stack-protector

OS := $(shell uname)
ifeq ($(OS),Darwin)
	# for M1 machines with Rosetta homebrew in /opt
	PKG_CONFIG_PATH = "$(shell echo $PKG_CONFIG_PATH):/opt/homebrew/opt/openssl/lib/pkgconfig"
	PC_LIBS := $(shell env PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)" pkg-config --libs openssl)
	PC_INCLUDES := $(shell env PKG_CONFIG_PATH="$(PKG_CONFIG_PATH)" pkg-config --cflags openssl)
	SDK_PATH := /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
	SDK_LIBS := -L$(SDK_PATH) -lSystem
	LDLIB := -lpam -lSystem -L$(SDK_PATH)/usr/lib $(PC_LIBS)
	LDINCLUDE := -I$(SDK_PATH)/usr/include $(PC_INCLUDES)
	LDFLAGS := -x -dylib
	# otherwise stdlib.h has hundreds of warnings...
	CFLAGS := $(CFLAGS) -Wno-nullability-completeness -Wno-pointer-sign
	PAM_DIR := /usr/local/lib/pam
else
	LDLIB := -lpam -lpam_misc -lssl -lcrypto -lc
	LDINCLUDE := $(LDLIB)
	LDFLAGS := -x -shared
	PAM_DIR := /lib/security
endif

BIN_INSTALL := /usr/local/bin

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

.PHONY: all
all: $(OBJS) $(BIN_DIR)/duress_sign $(BIN_DIR)/pam_test $(BIN_DIR)/pam_duress.so

install: $(BIN_DIR)/pam_duress.so $(BIN_DIR)/duress_sign $(BIN_DIR)/pam_test
	mkdir -p $(PAM_DIR)
	cp $(BIN_DIR)/pam_duress.so $(PAM_DIR)/
	cp $(BIN_DIR)/duress_sign $(BIN_INSTALL)/
	cp $(BIN_DIR)/pam_test $(BIN_INSTALL)/

$(OBJS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< $(LDINCLUDE) -o $@

$(BIN_DIR)/duress_sign: $(OBJS)
	mkdir -p $(BIN_DIR)
	$(CC) -o $@ $(OBJ_DIR)/duress_sign.o $(OBJ_DIR)/util.o $(LDLIB)

$(BIN_DIR)/pam_duress.so:  $(OBJS)
	ld $(LDFLAGS) -o $@ $(OBJ_DIR)/duress.o $(OBJ_DIR)/util.o $(LDLIB)

$(BIN_DIR)/pam_test:
	mkdir -p $(BIN_DIR)
	$(CC) -o $@ src/pam_test.c $(LDLIB)

.PHONY: uninstall
uninstall:
	rm -rf $(PAM_DIR)/pam_duress.so
	rm -rf $(BIN_INSTALL)/duress_sign
	rm -rf $(BIN_INSTALL)/pam_test

.PHONY: clean
clean:
	rm -rf $(OBJ_DIR)/*.o
	rm -rf $(BIN_DIR)/*
