/* Copyright (c) 1999 Ng Pheng Siong. All rights reserved. */
/* $Id: _lib.h 299 2005-06-09 17:32:28Z heikki $ */

typedef struct _blob {
	unsigned char *data;
	int len;
} Blob;

Blob *blob_new(int len, const char *errmsg);
Blob *blob_copy(Blob *from, const char *errmsg);
void blob_free(Blob *blob);

void gen_callback(int p, int n, void *arg);
int passphrase_callback(char *buf, int num, int v, void *userdata);

void lib_init(void);

