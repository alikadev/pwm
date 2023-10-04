#include <string.h>
#include <errno.h>
#include <stdint.h>

#include "pwm.h"

extern int errno;

#define PWM_PASSWORD_MIN_LENGTH 8
#define PWM_PASSWORD_MAX_LENGTH 128
#define PWM_DESCR_MAX 1024

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
	printf("  %s create <file>\n", *argv);
	printf("  %s add <file> <key> <descr>\n", *argv);
	//printf("  %s rem <file> <passwd> <key>\n", *argv);
	//printf("  %s get <file> <passwd>\n", *argv);
	printf("  %s get <file>\n", *argv);
	exit(EXIT_FAILURE);
	return EXIT_FAILURE;
}


void pwm_create(int argc, char const **argv)
{
	int status;
	FILE *file = NULL;
	const char *filename = NULL;
	char password[PWM_PASSWORD_MAX_LENGTH] = {0};
	uint8_t hash[SHA256_DIGEST_LENGTH] = {0};

	// Check the arguments
	if (argc != 3)
	{
		errorf("Bad arguments for function create!\n");
		printf("Usage:\n");
		printf("  %s create <file>\n", *argv);
		printf("<file> is the pwm file that will be created.\n");
		goto failure;
	}

	// Get the arguments
	filename = argv[2];
	status = EVP_read_pw_string_min(
				password,
				PWM_PASSWORD_MIN_LENGTH, 
				PWM_PASSWORD_MAX_LENGTH,
                "PWM password> ", 
                1);
	if (status != 0)
	{
		errorf("Fail to read the password\n");
		return;
	}

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
	debugf("Writing the PWM_MAGIC (%s)\n", PWM_MAGIC);
	fprintf(file, "%s", PWM_MAGIC);
	debugf("Writing the HASH\n");
	fprintf(file, "%s", hash);

	// Close the file
	printf("PWM-File '%s' successfully created\n", filename);
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
	char password[PWM_PASSWORD_MAX_LENGTH] = {0};
	uint8_t hash[SHA256_DIGEST_LENGTH] = {0};

	// Check the arguments
	if (argc != 3)
	{
		errorf("Bad arguments for function get!\n");
		printf("Usage:\n");
		printf("  %s get <file>\n\n", *argv);
		printf("<file> is the pwm file that will be created.\n");

		goto failure;
	}

	// Get the arguments
	filename = argv[2];
	status = EVP_read_pw_string_min(
				password,
				PWM_PASSWORD_MIN_LENGTH, 
				PWM_PASSWORD_MAX_LENGTH,
                "PWM password> ", 
                0);
	if (status != 0)
	{
		errorf("Fail to read the password\n");
		return;
	}

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
	char password[PWM_PASSWORD_MAX_LENGTH] = {0};
	const char *key = NULL;
	char descr[PWM_DESCR_MAX] = {0};
	uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
	char *keyCipher = NULL;
	char *descrCipher = NULL;
	uint32_t keyCipherLen;
	uint32_t descrCipherLen;

	// Check the arguments
	if (argc != 4)
	{
		errorf("Bad arguments for function add!\n");
		printf("Usage:\n");
		printf("  %s add <file> <key>\n\n", *argv);
		printf("<file> is the pwm file that will be created.\n");
		printf("<key> is the id of the element.\n");
		goto failure;
	}

	// Get the arguments
	filename = argv[2];
	key = argv[3];

	do {
		status = pwm_readline("Descr> ", descr, PWM_DESCR_MAX);
		if (status == PWM_TOO_LONG)
			errorf("String too long. Max size is %d\n", PWM_DESCR_MAX);
	} while(status != PWM_SUCCESS);

	status = EVP_read_pw_string_min(
				password,
				PWM_PASSWORD_MIN_LENGTH, 
				PWM_PASSWORD_MAX_LENGTH,
                "PWM password> ", 
                0);
	if (status != 0)
	{
		errorf("Fail to read the password\n");
		return;
	}

	pwm_hash(hash, password);

	debugf("filename: %s\n", filename);
	debugf("password: ");
	print_hash(hash);
	debugf("key: %s\n", key);
	debugf("description: %s\n", descr);

	// Check the file format and the hash
	debugf("Checking file identity\n");
	status = pwm_check_file_identity(filename, hash);
	if (status == PWM_FAILURE)
		goto failure;

	// Encrypt the data
	debugf("Encrypting the element\n");
	status = pwm_encrypt_element(
			hash, SHA256_DIGEST_LENGTH,
			&keyCipher, &descrCipher,
			key, descr);
	if (status == PWM_FAILURE)
		goto failure;
	debugf("File identity is OK");

	keyCipherLen = (uint32_t)strlen(keyCipher) + 1;
	descrCipherLen = (uint32_t)strlen(descrCipher) + 1;
	debugf("LENGTHS = %d, %d\n", keyCipherLen, descrCipherLen);
	debugf("CIPHER = \n");
	print_hash((uint8_t*)keyCipher);
	print_hash((uint8_t*)descrCipher);

	// Open the file in append mode
	debugf("Opening the file '%s'\n", filename);
	file = fopen(filename, "ab");
	if (!file)
	{
		errorf("Fail to open the file '%s' > %s\n",
			filename, strerror(errno));
		goto failure;
	}
	fseek(file, 0, SEEK_END);

	// Write the data into the file
	debugf("Writing the key...\n");
	fwrite(&keyCipherLen, sizeof keyCipherLen, 1, file);
	fputs(keyCipher, file);
	debugf("Writing the descr...\n");
	fwrite(&descrCipherLen, sizeof descrCipherLen, 1, file);
	fputs(descrCipher, file);

	// Finish! :)
	printf("The element has been successfully inserted\n");
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

int pwm_readline(char *prompt, char *buff, size_t sz) {
    int ch, extra;

    // Get line with buffer overrun protection.
    if (prompt != NULL) {
        printf ("%s", prompt);
        fflush (stdout);
    }
    if (fgets (buff, sz, stdin) == NULL)
        return PWM_NO_INPUT;

    // If it was too long, there'll be no newline. In that case, we flush
    // to end of line so that excess doesn't affect the next call.
    if (buff[strlen(buff)-1] != '\n') {
        extra = 0;
        while (((ch = getchar()) != '\n') && (ch != EOF))
            extra = 1;
        return (extra == 1) ? PWM_TOO_LONG : PWM_SUCCESS;
    }

    // Otherwise remove newline and give string back to caller.
    buff[strlen(buff)-1] = '\0';
    return PWM_SUCCESS;
}
