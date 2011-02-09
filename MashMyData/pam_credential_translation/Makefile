#
# MashMyData Project
#
# Author: P J Kershaw
#
# Date: 24/11/10
#
# Description: Build PAM Service module for MyProxyCA Credential
#	       Translation Service
#
# Copyright: (C) 2010 STFC
#
# License: BSD - LICENSE file
#
# $Id$
OBJS =		pam_credential_translation.o
SHARED =	$(OBJS:%.o=%.so)
SHARED_LIB =	$(OBJS:%.o=%)

TEST_OBJS =	test_pam_credential_translation.o
TEST_TARGET =	$(TEST_OBJS:%.o=%)

CFLAGS =	-O2 -g -Wall -fmessage-length=0 -fPIC
LDFLAGS = 	-shared -fPIC
LIBS = 		-L. -Wl,-R. $(SHARED) -lpam -lpam_misc -lssl

# This location may vary with different Linux distros
PAM_LIB_DIR = 	/lib/security/
PAM_LIB_FILEMASK = 644

$(SHARED):	$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $@

$(TEST_TARGET):	$(SHARED) $(TEST_OBJS)
	$(CC) $(CFLAGS) $(LIBS) $(TEST_OBJS) -o $@

install:	$(SHARED)
	cp $(SHARED) $(PAM_LIB_DIR)
	chmod $(PAM_LIB_FILEMASK) $(PAM_LIB_DIR)$(SHARED) 

clean:
	rm -f $(OBJS) $(SHARED)
	rm -f $(TEST_OBJS) $(TEST_TARGET)
