libcrypter - C / C++ Crypter Library!

# API

```
#include "crypter.h"

struct crypter_result {
	char * string;
	int size;
};

struct crypter_result crypter (char *input, unsigned input_length, char *password, unsigned password_length)
```


# Demo (demo.c)

Compile 

```
gcc -o demo demo.c crypter.c $(perl -MExtUtils::Embed -e ccopts -e ldopts) 
```

Run 

```
./demo Hello 123456
```

# Code

```
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
```
