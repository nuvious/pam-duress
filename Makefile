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

all: $(OBJS) duress_sign pam_test pam_duress.o

install: $(BIN_DIR)/pam_duress.o $(BIN_DIR)/duress_sign $(BIN_DIR)/pam_test
	mkdir -p $(PAM_DIR)
	cp $(BIN_DIR)/pam_duress.o $(PAM_DIR)/
	cp $(BIN_DIR)/duress_sign $(BIN_INSTALL)/
	cp $(BIN_DIR)/pam_test $(BIN_INSTALL)/

$(OBJS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< $(LDLIB) -o $@

duress_sign: $(OBJS)
	$(CC) -o $(BIN_DIR)/duress_sign $(OBJ_DIR)/duress_sign.o $(OBJ_DIR)/util.o $(LDLIB)

pam_duress.o:  $(OBJS)
	ld -x --shared -o $(BIN_DIR)/pam_duress.o $(OBJ_DIR)/duress.o $(OBJ_DIR)/util.o $(LDLIB)

pam_test:
	$(CPP) -o $(BIN_DIR)/pam_test src/pam_test.c $(LDLIB)

uninstall:
	rm -rf $(PAM_DIR)/pam_duress.o
	rm -rf $(BIN_INSTALL)/duress_sign
	rm -rf $(BIN_INSTALL)/pam_test

.PHONY: clean

clean:
	rm -rf $(OBJ_DIR)/*.o
	rm -rf $(BIN_DIR)/*
