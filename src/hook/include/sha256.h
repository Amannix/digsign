#ifndef _SHA256_H
#define _SHA256_H

#include <linux/types.h>
#include "../include/kstdio.h"
int sha256(FILE *thefile, unsigned long offset, unsigned long len, unsigned char *out);

#endif /* sha256_h */