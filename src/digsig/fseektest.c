/*************************************************************************
	> File Name: fseektest.c
	> Author: xmb
	> Mail: 1785175681@qq.com 
	> Created Time: 2020年04月17日 星期五 01时26分07秒
 ************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
int main ()
{	
	FILE *thefile = fopen("./ttest","rb+");
	int *pf = NULL;
	pf = realloc(pf, 10);
	if (thefile == NULL){
		return -1;
	}
	fread(pf,10,1,thefile);
	fseek(thefile, 1,SEEK_SET);
	fwrite(pf,10,1,thefile);
	fclose(thefile);
	realloc(pf,0);
	return 0;
}
