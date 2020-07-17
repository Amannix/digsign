/*base64.h*/  
#ifndef _BASE64_H
#define _BASE64_H
  
#include <stdlib.h>
#include <string.h>
  
unsigned char *base64_encode(unsigned char *str, int str_len);
  
int base64_decode(unsigned char *code, unsigned char **buf);
  
#endif  