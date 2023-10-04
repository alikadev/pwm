#include <string.h>
#include <errno.h>
#include <stdint.h>

#include "pwm.h"

extern int errno;


int main(int argc, char const **argv)
{
	if (argc < 2)
		 goto failure;

	const char *command = argv[1];
	if (strcmp(command, "create") == 0)
		pwm_create(argc, argv);
	else if (strcmp(command, "add") == 0)
		pwm_add(argc, argv);
	else if (strcmp(command, "rem") == 0)
		pwm_rem(argc, argv);
	else if (strcmp(command, "get") == 0)
		pwm_get(argc, argv);
	else goto failure;

	return 0;
failure:
	errorf("No function has beed passed!\n");
	printf("Usage:\n");
	printf("  %s create <file> <passwd>\n", *argv);
	printf("  %s add <file> <passwd> <key> \"<descr>\"\n", *argv);
	//printf("  %s rem <file> <passwd> <key>\n", *argv);
	//printf("  %s get <file> <passwd>\n", *argv);
	printf("  %s get <file> <passwd> <key>\n", *argv);
	exit(EXIT_FAILURE);
	return EXIT_FAILURE;
}


void pwm_create(int argc, char const **argv)
{
	FILE *file = NULL;
	const char *filename = NULL;
	const char *password = NULL;
	uint8_t hash[SHA256_DIGEST_LENGTH] = {0};

	// Check the arguments
	if (argc != 4)
	{
		errorf("Bad arguments for function create!\n");
		printf("Usage:\n");
		printf("  %s create <file> <passwd>\n", *argv);
		printf("<file> is the pwm file that will be created.\n");
		printf("<passwd> is the file password.\n");
		goto failure;
	}

	// Get the arguments
	filename = argv[2];
	password = argv[3];

	pwm_hash(hash, password);

	debugf("filename: %s\n", filename);
	debugf("password: "); 
	print_hash(hash);

	// Create the file
	file = fopen(filename, "wb");
	if (!file)
	{
		errorf("Fail to create the file > %s\n",
			strerror(errno));
		goto failure;
	}

	// Add all the data in the file
	fprintf(file, "%s", PWM_MAGIC);
	fprintf(file, "%s", hash);

	// Close the file
	fclose(file);
	return;
failure:
	if (file)
		fclose(file);
}

void pwm_get(int argc, char const **argv)
{
	int status;
	FILE *file = NULL;
	const char *filename = NULL;
	const char *password = NULL;
	uint8_t hash[SHA256_DIGEST_LENGTH] = {0};

	// Check the arguments
	if (argc != 4)
	{
		errorf("Bad arguments for function get!\n");
		printf("Usage:\n");
		printf("  %s get <file> <passwd>\n\n", *argv);
		printf("<file> is the pwm file that will be created.\n");
		printf("<passwd> is the file password.\n");

		goto failure;
	}

	// Get the arguments
	filename = argv[2];
	password = argv[3];

	pwm_hash(hash, password);

	debugf("filename: %s\n", filename);
	debugf("password: ");
	print_hash(hash);

	// Check the file format and the hash
	status = pwm_check_file_identity(filename, hash);
	if (status == PWM_FAILURE)
		goto failure;

	// Open the file in append mode
	file = fopen(filename, "rb");
	if (!file)
	{
		errorf("Fail to open the file '%s' > %s\n",
			filename, strerror(errno));
		goto failure;
	}

	// Encrypt the data
	fseek(file, PWM_HEADER_SIZE, SEEK_SET);

	while(!feof(file))
	{
		char *key = NULL;
		char *descr = NULL;
		char *keyCipher = NULL;
		char *descrCipher = NULL;
		uint32_t keyCipherLen;
		uint32_t descrCipherLen;
		// Read the key from the file
		fread(&keyCipherLen, sizeof keyCipherLen, 1, file);
		// - If the file is empty, eof will be set
		if (feof(file))
			break;
		keyCipher = malloc(keyCipherLen + 1);
		fgets(keyCipher, keyCipherLen, file);

		// Read the descr from the file
		fread(&descrCipherLen, sizeof descrCipherLen, 1, file);
		descrCipher = malloc(descrCipherLen + 1);
		fgets(descrCipher, descrCipherLen, file);

		debugf("LENGTHS = %d, %d\n", keyCipherLen, descrCipherLen);
		debugf("CIPHER = \n");
		print_hash((uint8_t*)keyCipher);
		print_hash((uint8_t*)descrCipher);

		// Decrypt the files
		pwm_decrypt_element(
				hash, SHA256_DIGEST_LENGTH,
				&key, &descr,
				keyCipher, descrCipher);
		printf("%s\n%s\n\n", key, descr);

		// Free the keys
		free(keyCipher);
		free(descrCipher);
	}

	// Finish! :)
	fclose(file);
	return;
failure:
	if (file)
		fclose(file);
}

void pwm_add(int argc, char const **argv)
{
	int status;
	FILE *file = NULL;
	const char *filename = NULL;
	const char *password = NULL;
	const char *key = NULL;
	const char *descr = NULL;
	uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
	char *keyCipher = NULL;
	char *descrCipher = NULL;
	uint32_t keyCipherLen;
	uint32_t descrCipherLen;

	// Check the arguments
	if (argc != 6)
	{
		errorf("Bad arguments for function add!\n");
		printf("Usage:\n");
		printf("  %s add <file> <passwd> <key> \"<descr>\"\n\n", *argv);
		printf("<file> is the pwm file that will be created.\n");
		printf("<passwd> is the file password.\n");
		printf("<key> is the id of the element.\n");
		printf("<descr> contains data about the element.\n");
		goto failure;
	}

	// Get the arguments
	filename = argv[2];
	password = argv[3];
	key = argv[4];
	descr = argv[5];

	pwm_hash(hash, password);

	debugf("filename: %s\n", filename);
	debugf("password: ");
	print_hash(hash);
	debugf("key: %s\n", key);
	debugf("description: %s\n", descr);

	// Check the file format and the hash
	status = pwm_check_file_identity(filename, hash);
	if (status == PWM_FAILURE)
		goto failure;

	// Encrypt the data
	status = pwm_encrypt_element(
			hash, SHA256_DIGEST_LENGTH,
			&keyCipher, &descrCipher,
			key, descr);
	if (status == PWM_FAILURE)
		goto failure;

	keyCipherLen = (uint32_t)strlen(keyCipher) + 1;
	descrCipherLen = (uint32_t)strlen(descrCipher) + 1;
	debugf("LENGTHS = %d, %d\n", keyCipherLen, descrCipherLen);
	debugf("CIPHER = \n");
	print_hash((uint8_t*)keyCipher);
	print_hash((uint8_t*)descrCipher);

	// Open the file in append mode
	file = fopen(filename, "ab");
	if (!file)
	{
		errorf("Fail to open the file '%s' > %s\n",
			filename, strerror(errno));
		goto failure;
	}

	// Write the data into the file
	fwrite(&keyCipherLen, sizeof keyCipherLen, 1, file);
	fputs(keyCipher, file);
	fwrite(&descrCipherLen, sizeof descrCipherLen, 1, file);
	fputs(descrCipher, file);

	// Finish! :)
	free(keyCipher);
	free(descrCipher);
	fclose(file);
	return;
failure:
	if (file)
		fclose(file);
	if (keyCipher)
		free(keyCipher);
	if (descrCipher)
		free(descrCipher);
}

void pwm_rem(int argc, char const **argv)
{
	(void) argc;
	(void) argv;
}

int pwm_check_file_identity(
	const char *filename, 
	uint8_t *hash)
{
	FILE *file;
	char bufferMagic[strlen(PWM_MAGIC)+1] = {0};
	char bufferHash[SHA256_DIGEST_LENGTH+1] = {0};

	// Open the file
	file = fopen(filename, "rb");
	if (!file)
	{
		errorf("Fail to open '%s' > %s\n", 
			filename, strerror(errno));
		goto failure;
	}

	// Check if it's really a PWM0 file
	fgets(bufferMagic, strlen(PWM_MAGIC)+1, file);
	if (strcmp(bufferMagic, PWM_MAGIC) != 0)
	{
		errorf("The file '%s' is not a PWM0 file!\n",
			filename);
		goto failure;
	}

	// Check the hash
	fgets(bufferHash, SHA256_DIGEST_LENGTH+1, file);
	if (strcmp(bufferHash, (char *)hash) != 0)
	{
		errorf("The file authentification failed!\n");
		goto failure;
	}

	fclose(file);
	return PWM_SUCCESS;
failure:
	if (file)
		fclose(file);
	return PWM_FAILURE;
}