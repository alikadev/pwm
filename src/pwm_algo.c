#include <string.h>
#include <errno.h>

#include "pwm.h"
#include <openssl/aes.h>

int pwm_encrypt_element(
	uint8_t *passwordHash, size_t passwordLen,
	char **pCipherKey, char **pCipherDescr,
	const char *key, const char *descr)
{
	size_t keyLen = strlen(key) + 1;
	size_t descrLen = strlen(descr) + 1;
	EVP_CIPHER_CTX* en = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX* de = EVP_CIPHER_CTX_new();
	int status;
	unsigned int salt[] = 
	{
		('P' << 8) ^ ('W' << 4) ^ 'M', 
		('V' << 8) ^ ('0' << 4) ^ '0'
	};

	status = pwm_aes_init(
			passwordHash, passwordLen, 
			(uint8_t*)&salt, en, de);
	if (status == PWM_FAILURE)
	{
		errorf("Fail to initialize the AES cipher\n");
		return PWM_FAILURE;
	}

	*pCipherKey = pwm_aes_encrypt(en, key, &keyLen);
	*pCipherDescr = pwm_aes_encrypt(en, descr, &descrLen);

	(*pCipherKey)[keyLen] = 0;
	(*pCipherDescr)[descrLen] = 0;

	return PWM_SUCCESS;
}

int pwm_decrypt_element(
	uint8_t *passwordHash, size_t passwordLen,
	char **pKey, char **pDescr,
	const char *cipherKey, const char *cipherDescr)
{
	size_t keyLen = strlen(cipherKey) + 1;
	size_t descrLen = strlen(cipherDescr) + 1;
	EVP_CIPHER_CTX* en = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX* de = EVP_CIPHER_CTX_new();
	int status;
	unsigned int salt[] = 
	{
		('P' << 8) ^ ('W' << 4) ^ 'M', 
		('V' << 8) ^ ('0' << 4) ^ '0'
	};

	status = pwm_aes_init(
			passwordHash, passwordLen, 
			(uint8_t*)&salt, en, de);
	if (status == PWM_FAILURE)
	{
		errorf("Fail to initialize the AES cipher\n");
		return PWM_FAILURE;
	}

	*pKey = pwm_aes_decrypt(de, cipherKey, &keyLen);
	*pDescr = pwm_aes_decrypt(de, cipherDescr, &descrLen);

	(*pKey)[keyLen] = 0;
	(*pDescr)[descrLen] = 0;

	return PWM_SUCCESS;
}

void pwm_hash(uint8_t *hash, const char *password)
{
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, password, strlen(password));
	SHA256_Final(hash, &sha256);
}

/*
 * Source: https://github.com/saju/misc/blob/master/misc/openssl_aes.c
 *
 * Create a 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 */
int pwm_aes_init(
	uint8_t *key_data, 
	int key_data_len, 
	uint8_t *salt, 
	EVP_CIPHER_CTX *e_ctx, 
	EVP_CIPHER_CTX *d_ctx)
{
	int i, nrounds = 5;
	uint8_t key[32], iv[32];
	
	/*
	 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
	 * nrounds is the number of times the we hash the material. More rounds are more secure but
	 * slower.
	 */
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
	if (i != 32) {
		printf("Key size is %d bits - should be 256 bits\n", i);
		return PWM_FAILURE;
	}

	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

	return PWM_SUCCESS;
}

/*
 * Source: https://github.com/saju/misc/blob/master/misc/openssl_aes.c
 *
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
char *pwm_aes_encrypt(
	EVP_CIPHER_CTX *e, 
	const char *plaintext, 
	size_t *len)
{
	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	uint8_t *ciphertext = malloc(c_len);

	/* allows reusing of 'e' for multiple encryption cycles */
	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

	/* update ciphertext, c_len is filled with the length of ciphertext generated,
	 *len is the size of plaintext in bytes */
	EVP_EncryptUpdate(e, ciphertext, &c_len, (const uint8_t *)plaintext, *len);

	/* update ciphertext with the final remaining bytes */
	EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

	*len = c_len + f_len;
	return (char *)ciphertext;
}

/*
 * Source: https://github.com/saju/misc/blob/master/misc/openssl_aes.c
 *
 * Decrypt *len bytes of ciphertext
 */
char *pwm_aes_decrypt(
	EVP_CIPHER_CTX *e, 
	const char *ciphertext, 
	size_t *len)
{
	/* plaintext will always be equal to or lesser than length of ciphertext*/
	int p_len = *len, f_len = 0;
	uint8_t *plaintext = malloc(p_len);
	
	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, plaintext, &p_len, (uint8_t *)ciphertext, *len);
	EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

	*len = p_len + f_len;
	return (char*)plaintext;
}
