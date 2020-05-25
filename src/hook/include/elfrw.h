
#ifndef _elfrw_h_
#define _elfrw_h_

#include "kstdio.h"
#include <linux/elf.h>

typedef struct
{
  Elf64_Half si_boundto;		/* Direct bindings, symbol bound to */
  Elf64_Half si_flags;			/* Per symbol flags */
} Elf64_Syminfo;

typedef struct
{
  Elf64_Word	vna_hash;		/* Hash value of dependency name */
  Elf64_Half	vna_flags;		/* Dependency specific information */
  Elf64_Half	vna_other;		/* Unused */
  Elf64_Word	vna_name;		/* Dependency name string offset */
  Elf64_Word	vna_next;		/* Offset in bytes to next vernaux
					   entry */
} Elf64_Vernaux;

typedef struct
{
  Elf64_Word	vda_name;		/* Version or dependency names */
  Elf64_Word	vda_next;		/* Offset in bytes to next verdaux
					   entry */
} Elf64_Verdaux;

typedef struct
{
  Elf64_Half	vd_version;		/* Version revision */
  Elf64_Half	vd_flags;		/* Version information */
  Elf64_Half	vd_ndx;			/* Version Index */
  Elf64_Half	vd_cnt;			/* Number of associated aux entries */
  Elf64_Word	vd_hash;		/* Version name hash value */
  Elf64_Word	vd_aux;			/* Offset in bytes to verdaux array */
  Elf64_Word	vd_next;		/* Offset in bytes to next verdef
					   entry */
} Elf64_Verdef;

typedef struct
{
  Elf64_Half	vn_version;		/* Version of structure */
  Elf64_Half	vn_cnt;			/* Number of associated aux entries */
  Elf64_Word	vn_file;		/* Offset of filename for this
					   dependency */
  Elf64_Word	vn_aux;			/* Offset in bytes to vernaux array */
  Elf64_Word	vn_next;		/* Offset in bytes to next verneed
					   entry */
} Elf64_Verneed;

typedef Elf64_Half Elf64_Versym;



extern int elfrw_initialize_direct(unsigned char class, unsigned char data,
				   unsigned char version);

extern int elfrw_initialize_ident(unsigned char const *e_ident);


extern void elfrw_getsettings(unsigned char *class, unsigned char *data,
			      unsigned char *version);

extern int elfrw_read_Half(FILE *fp, Elf64_Half *in);
extern int elfrw_read_Word(FILE *fp, Elf64_Word *in);
extern int elfrw_read_Sword(FILE *fp, Elf64_Sword *in);
extern int elfrw_read_Xword(FILE *fp, Elf64_Xword *in);
extern int elfrw_read_Sxword(FILE *fp, Elf64_Sxword *in);
extern int elfrw_read_Addr(FILE *fp, Elf64_Addr *in);
extern int elfrw_read_Off(FILE *fp, Elf64_Off *in);
extern int elfrw_read_Versym(FILE *fp, Elf64_Versym *in);

extern int elfrw_read_Ehdr(FILE *fp, Elf64_Ehdr *in);
extern int elfrw_read_Shdr(FILE *fp, Elf64_Shdr *in);
extern int elfrw_read_Sym(FILE *fp, Elf64_Sym *in);
extern int elfrw_read_Syminfo(FILE *fp, Elf64_Syminfo *in);
extern int elfrw_read_Rel(FILE *fp, Elf64_Rel *in);
extern int elfrw_read_Rela(FILE *fp, Elf64_Rela *in);
extern int elfrw_read_Phdr(FILE *fp, Elf64_Phdr *in);
extern int elfrw_read_Dyn(FILE *fp, Elf64_Dyn *in);
extern int elfrw_read_Verdef(FILE *fp, Elf64_Verdef *in);
extern int elfrw_read_Verdaux(FILE *fp, Elf64_Verdaux *in);
extern int elfrw_read_Verneed(FILE *fp, Elf64_Verneed *in);
extern int elfrw_read_Vernaux(FILE *fp, Elf64_Vernaux *in);

extern int elfrw_read_Shdrs(FILE *fp, Elf64_Shdr *in, int count);
extern int elfrw_read_Syms(FILE *fp, Elf64_Sym *in, int count);
extern int elfrw_read_Syminfos(FILE *fp, Elf64_Syminfo *in, int count);
extern int elfrw_read_Rels(FILE *fp, Elf64_Rel *in, int count);
extern int elfrw_read_Relas(FILE *fp, Elf64_Rela *in, int count);
extern int elfrw_read_Phdrs(FILE *fp, Elf64_Phdr *in, int count);
extern int elfrw_read_Dyns(FILE *fp, Elf64_Dyn *in, int count);


extern int elfrw_write_Half(FILE *fp, Elf64_Half const *out);
extern int elfrw_write_Word(FILE *fp, Elf64_Word const *out);
extern int elfrw_write_Sword(FILE *fp, Elf64_Sword const *out);
extern int elfrw_write_Xword(FILE *fp, Elf64_Xword const *out);
extern int elfrw_write_Sxword(FILE *fp, Elf64_Sxword const *out);
extern int elfrw_write_Addr(FILE *fp, Elf64_Addr const *out);
extern int elfrw_write_Off(FILE *fp, Elf64_Off const *out);
extern int elfrw_write_Versym(FILE *fp, Elf64_Versym const *out);

extern int elfrw_write_Ehdr(FILE *fp, Elf64_Ehdr const *out);
extern int elfrw_write_Shdr(FILE *fp, Elf64_Shdr const *out);
extern int elfrw_write_Sym(FILE *fp, Elf64_Sym const *out);
extern int elfrw_write_Syminfo(FILE *fp, Elf64_Syminfo const *out);
extern int elfrw_write_Rel(FILE *fp, Elf64_Rel const *out);
extern int elfrw_write_Rela(FILE *fp, Elf64_Rela const *out);
extern int elfrw_write_Phdr(FILE *fp, Elf64_Phdr const *out);
extern int elfrw_write_Dyn(FILE *fp, Elf64_Dyn const *out);
extern int elfrw_write_Verdef(FILE *fp, Elf64_Verdef const *out);
extern int elfrw_write_Verdaux(FILE *fp, Elf64_Verdaux const *out);
extern int elfrw_write_Verneed(FILE *fp, Elf64_Verneed const *out);
extern int elfrw_write_Vernaux(FILE *fp, Elf64_Vernaux const *out);

extern int elfrw_write_Shdrs(FILE *fp, Elf64_Shdr const *out, int count);
extern int elfrw_write_Syms(FILE *fp, Elf64_Sym const *out, int count);
extern int elfrw_write_Syminfos(FILE *fp, Elf64_Syminfo const *out, int count);
extern int elfrw_write_Rels(FILE *fp, Elf64_Rel const *out, int count);
extern int elfrw_write_Relas(FILE *fp, Elf64_Rela const *out, int count);
extern int elfrw_write_Phdrs(FILE *fp, Elf64_Phdr const *out, int count);
extern int elfrw_write_Dyns(FILE *fp, Elf64_Dyn const *out, int count);

#endif
