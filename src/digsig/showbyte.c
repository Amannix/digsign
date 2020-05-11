#include <stdio.h>
#include <fcntl.h>
int main ()
{
	int fd;
	unsigned char buff[100];
	printf ("%x\n",'\n');
	fd = open("./ttest",O_RDONLY);
	if (fd < 1){
		printf ("fd err\n");
		return -1;
	}
	int size = 0;
	unsigned int count = 0;
	do{
		size = read(fd,buff,16);
		printf ("%08x -> ",count);
		for (int i = 0;i < size;++i){
			printf ("%02x",buff[i]);
			printf ("%s",(i+1)%4 ? "" : " ");
		}
		printf ("\n");
		count += size;
	}while (size > 0);

	return 0;
}
