struct crypter_result {
	char * string;
	int size;
};


struct crypter_result crypter (char *input, unsigned input_length, char *password, unsigned password_length, unsigned obfuscate);
struct crypter_result uncrypter (char *input, unsigned input_length, char *password, unsigned password_length, unsigned obfuscate);


