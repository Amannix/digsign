#ifndef _SHA256_H
#define _SHA256_H

#include <stdint.h>
void sha256(const unsigned char *data, size_t len, unsigned char *out);

#endif /* sha256_h */