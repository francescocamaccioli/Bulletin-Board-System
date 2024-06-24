#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>

#define BUF_SIZE 4096
#define TIMESTAMP_LEN 30
#define SELECT_SIZE 128
#define HMAC_SIZE 32
#define IV_SIZE 16
#define HASH_SIZE 32
#define SALT_LEN 16
#define CMDLEN 10
// users parameters lenghts
#define EMAIL_LEN 40
#define USERNAME_LEN 25
#define PWD_LEN 128
// messages parameters lenghts
#define TITLE_LEN 50
#define BODY_LEN 512
// color codes
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN    "\x1b[36m"
#define RESET   "\x1b[0m"

typedef struct message_auth{
    char timestamp[TIMESTAMP_LEN];
    unsigned char hmac[HMAC_SIZE];
} MessageAuth;

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

// function to encrypt a message using AES 256 ECB
void encrypt_message_AES256ECB(unsigned char* message, int message_len, unsigned char* key, unsigned char* ciphertext, int* ciphertext_len){
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx, EVP_aes_256_ecb(), key, NULL);
    int outlen;
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, message, message_len);
    *ciphertext_len = outlen;
    EVP_EncryptFinal(ctx, ciphertext + outlen, &outlen);
    *ciphertext_len += outlen;
    EVP_CIPHER_CTX_free(ctx);
}

// function to decrypt a message using AES 256 ECB
void decrypt_message_AES256ECB(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* plaintext, int* plaintext_len){
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, EVP_aes_256_ecb(), key, NULL);
    int outlen;
    EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, ciphertext_len);
    *plaintext_len = outlen;
    EVP_DecryptFinal(ctx, plaintext + outlen, &outlen);
    *plaintext_len += outlen;
    EVP_CIPHER_CTX_free(ctx);
}

// create timestamp string
char* create_timestamp(){
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char* timestamp = (char*)malloc(TIMESTAMP_LEN);
    // timestamp format: YYYY-MM-DD HH:MM:SS
    sprintf(timestamp, "%d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return timestamp;
}

MessageAuth createMessageAuth(unsigned char* hmac, unsigned int hmac_len){
    MessageAuth tosend;
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char timestamp[TIMESTAMP_LEN];
    // timestamp format: YYYY-MM-DD HH:MM:SS
    sprintf(timestamp, "%d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    memcpy(tosend.timestamp, timestamp, TIMESTAMP_LEN);
    memcpy(tosend.hmac, hmac, hmac_len);
    return tosend;
}

int checktimestamp(char* timestamp){
    // obtain the current timestamp
    time_t now = time(NULL);
    struct tm tm_now = *localtime(&now);
    char now_str[TIMESTAMP_LEN];
    // timestamp format: YYYY-MM-DD HH:MM:SS
    sprintf(now_str, "%d-%02d-%02d %02d:%02d:%02d", tm_now.tm_year + 1900, tm_now.tm_mon + 1, tm_now.tm_mday, tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec);

    // compare the timestamps: the received timestamp must be within 2 minutes from the current timestamp
    struct tm recv_tm;
    strptime(timestamp, "%Y-%m-%d %H:%M:%S", &recv_tm);
    time_t recv_time = mktime(&recv_tm);
    time_t diff = difftime(now, recv_time);
    if (diff > 60){
        printf("Timestamps differ by more than 1 minute, connection aborted\n");
        return 1;
    }
    else{
        printf("Timestamps differ by less than 1 minute, connection accepted\n");
        return 0;
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

void compute_sha256_salted(unsigned char *input, size_t input_len, char * hash, char* salt) {
    
    if(!salt){
        perror("need to allocate salt buffer first");
        exit(EXIT_FAILURE);
    }

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

    if (EVP_DigestUpdate(ctx, salt, SALT_LEN) != 1) {
        perror("EVP_DigestUpdate failed");
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx,(unsigned char*) hash, &hash_len) != 1) {
        perror("EVP_DigestFinal_ex failed");
        EVP_MD_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX_free(ctx);
}

int verify_sha256(unsigned char *input, size_t input_len, unsigned char *expected_hash) {
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

// function to concatenate the HMAC and the ciphertext in a single buffer
void concatenate_hmac_ciphertext(unsigned char* hmac, unsigned char* ciphertext, int ciphertext_size, unsigned char* buffer) {
    // Copy the HMAC to the beginning of the buffer
    memcpy(buffer, hmac, HMAC_SIZE);
    // Copy the ciphertext right after the HMAC in the buffer
    memcpy(buffer + HMAC_SIZE, ciphertext, ciphertext_size);
}

// function to split the HMAC and the ciphertext from a single buffer
void split_hmac_ciphertext(unsigned char* buffer, unsigned char* hmac, unsigned char* ciphertext, int ciphertext_size) {
    // Copy the HMAC from the beginning of the buffer
    memcpy(hmac, buffer, HMAC_SIZE);
    // Copy the ciphertext right after the HMAC in the buffer
    memcpy(ciphertext, buffer + HMAC_SIZE, ciphertext_size);
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

// function to generate an IV and send it together with the HMAC computed with a shared secret
void iv_comm(int selind, unsigned char* iv, unsigned char* shared_secret, int shared_secret_len){
    // generate a random IV
    RAND_poll();
    RAND_bytes(iv, 16);

    // send the IV to the client
    checkreturnint(send(selind, (void*)iv, 16, 0), "error sending IV");
    // generate the IV HMAC
    unsigned char* iv_hmac;
    unsigned int iv_hmac_len;
    iv_hmac = (unsigned char*)malloc(HMAC_SIZE);
    compute_hmac(iv, 16, shared_secret, shared_secret_len, iv_hmac, &iv_hmac_len);
    // send the IV HMAC to the client
    checkreturnint(send(selind, (void*)iv_hmac, HMAC_SIZE, 0), "error sending IV HMAC");
    //printf("IV HMAC sent\n");
    free(iv_hmac);
}

// function to receive IV and HMAC and check if they are correct
int receiveIVHMAC(int lissoc, unsigned char* iv, unsigned char* shared_secret, size_t shared_secret_len){
    // receive the IV
    int ret = recv(lissoc, (void*)iv, 16, 0);
    if (ret < 0){
        perror("error receiving IV");
        return -1;
    }
    // receive the IV HMAC
    unsigned char* iv_hmac = malloc(HMAC_SIZE);
    ret = recv(lissoc, (void*)iv_hmac, HMAC_SIZE, 0);
    if (ret < 0){
        perror("error receiving IV HMAC");
        return -1;
    }
    // compute the HMAC of the IV
    unsigned char* iv_hmac_comp=(unsigned char*)malloc(HMAC_SIZE);
    // check if malloc worked
    if (!iv_hmac_comp){
        perror("malloc failed");
        return -1;
    }
    int iv_hmac_len_comp;
    compute_hmac(iv, 16, shared_secret, shared_secret_len, iv_hmac_comp, &iv_hmac_len_comp);
    // check if the HMACs are equal
    if (memcmp(iv_hmac, iv_hmac_comp, HMAC_SIZE) != 0){
        puts("IV HMACs are different, aborting");
        return -1;
    }
    else{
        puts("IV HMACs are equal, parameters accepted");
    }
    free(iv_hmac);
    free(iv_hmac_comp);
    return 0;
}