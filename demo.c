#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypter.h"


void main (int argc, char *argv[]) {
	char *input, *password, *obfuscate;

	if (argc != 4) return;

	input = argv[1];	
	password = argv[2];
	obfuscate = argv[3];

	struct crypter_result r = crypter(input, strlen(input), password, strlen(password), atoi(obfuscate));

	for (int i = 0 ; i < r.size ; i ++) {
		fputc(r.string[i], stdout);
	}
}
