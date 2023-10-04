#ifndef PWM_H
#define PWM_H

/* LIBRARIES */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>


/* CONSTANTS OF PWM */
#define PWM_FAILURE 0
#define PWM_SUCCESS 1
#define PWM_MAGIC "PWM0"
#define PWM_HEADER_SIZE (sizeof(PWM_MAGIC) + SHA256_DIGEST_LENGTH - 1)


/* HELPER MACROS */
#ifdef DEBUG
	#define debugf(a ...) printf("DEBUG: " a)
#else
	#define debugf(...)
#endif

#define errorf(a ...) fprintf(stderr, "Error: " a)

#ifdef DEBUG
static void print_hash(const uint8_t *string)
{
	while (*string) printf("%02x", *string++);
	printf("\n");
}
#else
	#define print_hash(x)
#endif


/* FUNCTION DECLARATION*/

void pwm_hash(uint8_t *hash, const char *password);
void pwm_create(int argc, char const **argv);
void pwm_get(int argc, char const **argv);
void pwm_add(int argc, char const **argv);
void pwm_rem(int argc, char const **argv);
int pwm_check_file_identity(
			const char *filename, 
			uint8_t *hash);
int pwm_encrypt_element(
			uint8_t *passwordHash, 
			size_t passwordLen,
			char **pCipherKey, 
			char **pCipherDescr,
			const char *key, 
			const char *descr);
int pwm_decrypt_element(
			uint8_t *passwordHash, 
			size_t passwordLen,
			char **pKey, 
			char **pDescr,
			const char *cipherKey, 
			const char *cipherDescr);
int pwm_aes_init(
			uint8_t *key_data, 
			int key_data_len, 
			uint8_t *salt, 
			EVP_CIPHER_CTX *e_ctx, 
			EVP_CIPHER_CTX *d_ctx);
char *pwm_aes_encrypt(
			EVP_CIPHER_CTX *e, 
			const char *plaintext, 
			size_t *len);
char *pwm_aes_decrypt(
			EVP_CIPHER_CTX *e, 
			const char *ciphertext, 
			size_t *len);

#endif // PWM_H