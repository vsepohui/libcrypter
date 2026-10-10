#include <stdio.h>
#include <string.h>
#include "crypter.h"


void main (int argc, char *argv[]) {
    char *input = NULL;
    unsigned input_length = 0;   
    char *password = NULL;
    unsigned password_length = 0;   
    
    if (argc != 3) {
		return;
	}
    
    
	input = argv[1];	
	password = argv[2];
	input_length = strlen(input);
	password_length = strlen(password);
		
	struct crypter_result r = crypter(input, input_length, password, password_length);
	
	for (int i = 0 ; i < r.size ; i ++) {
		fputc(r.string[i], stdout);
	}
}
