/*
 * main.c
 *
 *  Created on: Mar 30, 2011
 *      Author: Dominic Fischer, Daniel Jordi
 */

#include <cstdio>
#include <cstdlib>

char key = 0x88;
char another_key = 0x99;

char DATA[] = //"Malflare is powerful! Greets from the developers...";
		{ 0xc5, 0xe8, 0xe6, 0xed, 0xe0, 0xec, 0xfc, 0xea, 0xb0, 0xf8, 0xe1,
				0xb3, 0xe4, 0xfa, 0xe1, 0xf2, 0xea, 0xff, 0xef, 0xf7, 0xbd,
				0xbd, 0xd9, 0xed, 0xc5, 0xc4, 0xd6, 0xd0, 0x84, 0xc3, 0xd4,
				0xc8, 0xc5, 0x89, 0xde, 0xc3, 0xc9, 0x8d, 0xca, 0xca, 0xc6,
				0xd4, 0xde, 0xdc, 0xc4, 0xd0, 0xc4, 0xc4, 0x96, 0x97, 0x94,
				0xbb, };
char DATA2[] = //"This DLL is harmless...guaranteed";
		{ 0xe8, 0xd5, 0xd7, 0xcc, 0xe0, 0x85, 0x8e, 0x8f, 0xe4, 0xac, 0xb5,
				0xe7, 0xa0, 0xa8, 0xb8, 0xa6, 0xa0, 0xa8, 0xbd, 0xbc, 0xfe,
				0xff, 0xfc, 0xb4, 0xa1, 0xb4, 0xa4, 0xb6, 0xb6, 0xad, 0xbf,
				0xbe, 0xb8, 0xdd, };
char FILE_PATH[] = //"goodflare.dll";
		{ 0xb9, 0xb0, 0x8f, 0x85, 0x84, 0x8f, 0x85, 0x97, 0x83, 0xc9, 0x8c,
				0x85, 0x86, 0xeb, 0x00 };

/**
 * This is not the real decryption function (deadcode)
 */
void decrypt2(char *buffer, int size, const char *data) {
	int i;

	for (i = 0; i < size; i++) {
		buffer[i] = data[i] ^ another_key;
	}

}

/**
 * Decrypt
 **/
void decrypt(char *buffer, int size, const char *data) {
	int i;

	for (i = 0; i < size; i++) {
		if (data[i] == 0x00) {
			break;
		} else if (1 == 2) { // deadcode
			int j = i * 2 + 0xDEADC0DE;

			decrypt2(buffer, size, data);
		}
		buffer[i] = data[i] ^ (key++ % 0x100);
		// Used to encrypt things
		//		printf("0x%02x, ", (unsigned char) buffer[i]);
	}
	// Used to encrypt things
	//	printf("\n");
}

/**
 * Main
 **/
int main() {

	/**
	 * Decrypting things
	 */
	char *data = (char *)malloc(sizeof(DATA));
	printf("Decrypting first chunk with %i bytes... \n", sizeof(DATA));
	decrypt(data, sizeof(DATA), DATA);

	char *data2 = (char *)malloc(sizeof(DATA));
	printf("Decrypting second chunk with %i bytes... \n", sizeof(DATA2));
	decrypt(data2, sizeof(DATA2), DATA2);

	char* file_path = (char *)malloc(sizeof(FILE_PATH));
	printf("Decrypting file path with %i bytes... \n", sizeof(FILE_PATH));
	decrypt(file_path, sizeof(FILE_PATH), FILE_PATH);

	/**
	 * Write things to a file
	 */
	FILE* file_handle;
	file_handle = fopen(file_path, "w");
	fwrite(data, 1, sizeof(DATA), file_handle);
	fwrite("\n", 1, 1, file_handle);
	fwrite(data2, 1, sizeof(DATA2), file_handle);
	fclose(file_handle);

	/**
	 * Free up
	 */
	free(data);
	free(data2);
	free(file_path);

	return 0;
}
