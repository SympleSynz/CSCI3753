# File: Makefile
# By: Andy Sayler <www.andysayler.com>
# Adopted from work by: Chris Wailes <chris.wailes@gmail.com>
# Project: CSCI 3753 Programming Assignment 5
# Creation Date: 2010/04/06
# Modififed Date: 2012/04/12
# Description:
#	This is the Makefile for PA5.


CC           = gcc

CFLAGSFUSE   = `pkg-config fuse --cflags`
LLIBSFUSE    = `pkg-config fuse --libs`
LLIBSOPENSSL = -lcrypto

CFLAGS = -c -g -Wall -Wextra
LFLAGS = -g -Wall -Wextra

FUSE_PA5 = PA5_EncryptFileSys
#FUSE_EXAMPLES = fusehello fusexmp 
#XATTR_EXAMPLES = xattr-util
#OPENSSL_EXAMPLES = aes-crypt-util 

.PHONY: all fuse-PA5 clean

all: fuse-PA5

#fuse-examples: $(FUSE_EXAMPLES)
#xattr-examples: $(XATTR_EXAMPLES)
#openssl-examples: $(OPENSSL_EXAMPLES)
fuse-PA5: $(FUSE_PA5)

#fusehello: fusehello.o
#	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSFUSE)

#fusexmp: fusexmp.o
#	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSFUSE)

PA5_EncryptFileSys: PA5_EncryptFileSys.o aes-crypt.o
	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSFUSE) $(LLIBSOPENSSL)

#xattr-util: xattr-util.o
#	$(CC) $(LFLAGS) $^ -o $@

#aes-crypt-util: aes-crypt-util.o aes-crypt.o
#	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSOPENSSL)

#fusehello.o: fusehello.c
#	$(CC) $(CFLAGS) $(CFLAGSFUSE) $<

PA5_EncryptFileSys.o: PA5_EncryptFileSys.c aes-crypt.h
	$(CC) $(CFLAGS) $(CFLAGSFUSE) $<

#fusexmp.o: fusexmp.c
#	$(CC) $(CFLAGS) $(CFLAGSFUSE) $<

#xattr-util.o: xattr-util.c
#	$(CC) $(CFLAGS) $<

#aes-crypt-util.o: aes-crypt-util.c aes-crypt.h
#	$(CC) $(CFLAGS) $<

aes-crypt.o: aes-crypt.c aes-crypt.h
	$(CC) $(CFLAGS) $<

clean:
	rm -f $(FUSE_PA5)
	rm -f *.o
	rm -f *~
	rm -f handout/*~
	rm -f handout/*.log
	rm -f handout/*.aux
	rm -f handout/*.out



