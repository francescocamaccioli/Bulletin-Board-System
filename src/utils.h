#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#define BUF_SIZE 4096
#define DATE_LEN 30
#define SELECT_SIZE 128
#define HMAC_SIZE 32
#define IV_SIZE 16
#define CMDLEN 10
#define EMAIL_LEN 40
#define USERNAME_LEN 20
#define PWD_LEN 128

void checkreturnint(int ret, char* msg){
   if(ret < 0){
      perror(msg);
      exit(EXIT_FAILURE);
   }
}

void checkrnull(void* ret, char* msg){
   if(!ret){
      perror(msg);
      exit(EXIT_FAILURE);
   }
}

void compute_sha256(unsigned char *input, size_t input_len, unsigned char *hash) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        perror("EVP_MD_CTX_new failed");
        exit(EXIT_FAILURE);
    }

    if(!hash){
        perror("need to allocate hash buffer first");
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        perror("EVP_DigestInit_ex failed");
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestUpdate(ctx, input, input_len) != 1) {
        perror("EVP_DigestUpdate failed");
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        perror("EVP_DigestFinal_ex failed");
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(ctx);
}

int verify_sha256(unsigned char *input, size_t input_len,unsigned char *expected_hash) {
    unsigned char computed_hash[SHA256_DIGEST_LENGTH];
    compute_sha256(input, input_len, computed_hash);
    return memcmp(computed_hash, expected_hash, SHA256_DIGEST_LENGTH) == 0;
}

// encrypt a message using AES 256 CBC
void encrypt_message(unsigned char* message, int message_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext, int* ciphertext_len){
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv);
    int outlen;
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, message, message_len);
    *ciphertext_len = outlen;
    EVP_EncryptFinal(ctx, ciphertext + outlen, &outlen);
    *ciphertext_len += outlen;
    EVP_CIPHER_CTX_free(ctx);
}

// decrypt a message using AES 256 CBC
void decrypt_message(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext, int* plaintext_len){
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv);
    int outlen;
    EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, ciphertext_len);
    *plaintext_len = outlen;
    EVP_DecryptFinal(ctx, plaintext + outlen, &outlen);
    *plaintext_len += outlen;
    EVP_CIPHER_CTX_free(ctx);
}

// function to compute the HMAC of a message
void compute_hmac(unsigned char* message, int message_len, unsigned char* key, int key_len, unsigned char* hmac, unsigned int* hmac_len){
    HMAC_CTX* ctx;
    ctx = HMAC_CTX_new();
    HMAC_Init(ctx, key, key_len, EVP_sha256());
    HMAC_Update(ctx, message, message_len);
    HMAC_Final(ctx, hmac, hmac_len);
    HMAC_CTX_free(ctx);
}