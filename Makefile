BIN_DIR := bin
OBJ_DIR := obj
SRC_DIR := src
CC := gcc
CPP := g++
CFLAGS := -fPIC -fno-stack-protector
LDLIB := -lssl -lcrypto -lpam -lpam_misc -lc
PAM_DIR := /lib/security
BIN_INSTALL := /usr/bin

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
	$(CC) $(CFLAGS) -c $< $(LDLIB) -o $@

$(BIN_DIR)/duress_sign: $(OBJS)
	mkdir -p $(BIN_DIR)
	$(CC) -o $@ $(OBJ_DIR)/duress_sign.o $(OBJ_DIR)/util.o $(LDLIB)

$(BIN_DIR)/pam_duress.so:  $(OBJS)
	ld -x --shared -o $@ $(OBJ_DIR)/duress.o $(OBJ_DIR)/util.o $(LDLIB)

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
