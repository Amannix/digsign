#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <elf.h>

#include "elfrw.h"

#ifndef TRUE
#define	TRUE	1
#define	FALSE	0
#endif

/* The online help text.
*/
static char const *yowzitch =
"Usage: sstrip [OPTIONS] FILE...\n"
"Remove all nonessential bytes from executable ELF files.\n\n"
"  -z, --zeroes        Also discard trailing zero bytes.\n"
"      --help          Display this help and exit.\n"
"      --version       Display version information and exit.\n";

/* Version and license information.
*/
static char const *vourzhon =
"sstrip, version 2.1\n"
"Copyright (C) 1999,2011 by Brian Raiter <breadbox@muppetlabs.com>\n"
"License GPLv2+: GNU GPL version 2 or later.\n"
"This is free software; you are free to change and redistribute it.\n"
"There is NO WARRANTY, to the extent permitted by law.\n";

/* The name of the program.
*/
static char const *theprogram;

/* TRUE if we should attempt to truncate zero bytes from the end of
 * the file.
 */
static int dozerotrunc = FALSE;

/* Information for each executable operated upon.
*/
static char const  *thefilename;	/* the name of the current file */
static FILE        *thefile;		/* the currently open file handle */
static Elf64_Ehdr   ehdr;		/* the current file's ELF header */
static Elf64_Phdr  *phdrs;		/* the program segment header table */
unsigned long       newsize;		/* the proposed new file size */

Elf64_Shdr apped_shdr;

/* A simple error-handling function. FALSE is always returned for the
 * convenience of the caller.
 */
static int err(char const *errmsg)
{
	fprintf(stderr, "%s: %s: %s\n", theprogram, thefilename, errmsg);
	return FALSE;
}

/* A macro for I/O errors: The given error message is used only when
 * errno is not set.
 */
#define	ferr(msg) (err(ferror(thefile) ? strerror(errno) : (msg)))

static int readelfheader(void)
{
	if (elfrw_read_Ehdr(thefile, &ehdr) != 1)
		return ferr("not a valid ELF file");

	if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN)
		return err("not an executable or shared-object library.");

	return TRUE;
}

/* readphdrtable() loads the program segment header table into memory.
*/
static int readphdrtable(void)
{
	if (!ehdr.e_phoff || !ehdr.e_phnum)
		return err("ELF file has no program header table.");

	if (!(phdrs = realloc(phdrs, ehdr.e_phnum * sizeof *phdrs)))
		return err("Out of memory!");
	if (elfrw_read_Phdrs(thefile, phdrs, ehdr.e_phnum) != ehdr.e_phnum)
		return ferr("missing or incomplete program segment header table.");

	return TRUE;
}

/* getmemorysize() determines the offset of the last byte of the file
 * that is referenced by an entry in the program segment header table.
 * (Anything in the file after that point is not used when the program
 * is executing, and thus can be safely discarded.)
 */
static int getmemorysize(void)
{
	unsigned long size, n;
	int i;

	/* Start by setting the size to include the ELF header and the
	 * complete program segment header table.
	 */
	size = ehdr.e_phoff + ehdr.e_phnum * sizeof *phdrs;
	if (size < ehdr.e_ehsize)
		size = ehdr.e_ehsize;

	/* Then keep extending the size to include whatever data the
	 * program segment header table references.
	 */
	for (i = 0 ; i < ehdr.e_phnum ; ++i) {
		if (phdrs[i].p_type != PT_NULL) {
			n = phdrs[i].p_offset + phdrs[i].p_filesz;
			if (n > size)
				size = n;
		}
	}

	newsize = size;
	return TRUE;
}


/* modifyheaders() removes references to the section header table if
 * it was stripped, and reduces program header table entries that
 * included truncated bytes at the end of the file.
 */
static int modifyheaders(void)
{
	return TRUE;
}

/* commitchanges() writes the new headers back to the original file
 * and sets the file to its new size.
 */
static int commitchanges(void)
{

	return TRUE;

warning:
	return err("ELF file may have been corrupted!");
}

/* main() loops over the cmdline arguments, leaving all the real work
 * to the other functions.
 */
int main(int argc, char *argv[])
{
	thefile = fopen("./hello","rb+");
	if (thefile == NULL){
		err(strerror(errno));
		return -1;
	}
	
	/*fseek(thefile, 0, 0);
	fwrite("1234", 4, 1, thefile);
	fclose(thefile);*/
	readelfheader();
	printf ("%u ",ehdr.e_shoff);
	ehdr.e_shnum++;
	//ehdr.e_shoff += 64;
	printf ("%u ",ehdr.e_shnum);
	printf ("%u ",ehdr.e_shentsize);
	printf ("-----------------\n");

	apped_shdr.sh_name = 0x1B;
	apped_shdr.sh_type = SHT_STRTAB;
	apped_shdr.sh_flags = SHF_MASKOS;
	apped_shdr.sh_addr = 0;
	apped_shdr.sh_offset = 0x18ef;
	apped_shdr.sh_size = 268;
	apped_shdr.sh_link = 0;
	apped_shdr.sh_info = 0;
	apped_shdr.sh_addralign = 1;
	apped_shdr.sh_entsize = 0;
	fseek(thefile, 0, SEEK_END);
	fwrite(&apped_shdr,sizeof (Elf64_Shdr),1,thefile);
	elfrw_write_Ehdr(thefile, (Elf64_Ehdr*)(&ehdr));
	int fd = fileno(thefile);
	fsync(fd);
//	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
	return 0;
}
