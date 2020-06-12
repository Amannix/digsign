
#ifndef _KSTDIO_H
#define _KSTDIO_H


#define TRUE 1
#define FALSE 0

#define SUCCESS 0
#define FILEERR 1
#define NOSIGERR 2
#define OTHERERR 3
#define FAULTERR 4


typedef struct file FILE;

int ferr(char *s);
int err(char *s);
void pdbug (unsigned char *buf,int len);
FILE *fopen(const char *path, int flags, int rights);
void fclose(FILE *file);
int fread(void *buf, unsigned int size, unsigned int count, FILE *fp);
//int fwrite(void *buf, unsigned int size, unsigned int count, FILE *fp);
int fseek(FILE *stream, long offset, int fromwhere);

#endif
