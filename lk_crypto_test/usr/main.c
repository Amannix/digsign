/*
 * main.c
 *
 *  Created on: May 30, 2018
 *      Author: alex
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void convert_file(char *filename)
{
	unsigned char c;
	FILE *file;
	int i;

	i = 1;
	printf("\"");
	file = fopen(filename, "rb");
	while (fread(&c, 1, 1, file)) {
		printf("\\x%02X", c);
		if (i % 16 == 0) {
			printf("\"\n\"");
		}
		i++;
	}
	if (i % 16 != 0)
		printf("\"\n");
}

void convert_string(char *str)
{
	int i;
	char *ptr = str;
	i = 1;
	printf("\"");

	while (*ptr != '\0') {
		printf("\\x%.2s", ptr);
		ptr+=2;
		if (i % 16 == 0) {
			printf("\"\n\"");
		}
		i++;
	}
	if (i % 16 != 0)
		printf("\"\n");
}

int main(int argc, char *argv[])
{

	if (!strcmp(argv[1], "-f")) {
		convert_file(argv[2]);
	}
	if (!strcmp(argv[1], "-s")) {
		convert_string(argv[2]);
	}

	return 0;
}
