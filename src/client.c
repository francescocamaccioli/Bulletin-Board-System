#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define BUF_SIZE 4096
#define SURN_MAX_LEN 1024
#define DATE_LEN 10
#define SELECT_SIZE 128

int login(int lissoc){
    printf("insert username: \n");
    char username [BUF_SIZE];
    scanf("%s", username);
    int size = strlen(username);
    uint8_t dim = htons(size);
    printf("username: %s\n", username);
    int ret = send(lissoc, (void*)&size, sizeof(uint8_t), 0);
    if (ret < 0){
        perror("error sending username length");
        exit(-1);
    }
    ret = send(lissoc, (void*)username, size, 0);
    if (ret < 0){
        perror("error sending username");
        exit(-1);
    }
    return 0;
}

int main(int argc, char* argv[]){
    int ret, lissoc;
    uint8_t dim;
    struct sockaddr_in srv_addr;
    char buffer [BUF_SIZE];
    uint16_t port = (uint16_t)strtol(argv[1], NULL, 10);
    lissoc= socket(AF_INET, SOCK_STREAM, 0);
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family=AF_INET;
    srv_addr.sin_port=htons(port);
    char* code = "5";
    inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);
    ret = connect(lissoc, (struct sockaddr*) &srv_addr, sizeof(srv_addr));
    if (ret < 0){
        perror("Errore nella connect \n");
        exit(-1);
    }
    // provando a fare hash sha256

    unsigned char* digest;
    int digestlen;
    EVP_MD_CTX* ctx;
    digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, (unsigned char*)code, sizeof(code));
    EVP_DigestFinal(ctx, digest, (unsigned int *) &digestlen);
    EVP_MD_CTX_free(ctx);
    for(int i = 0; i < digestlen; i++)
        printf("%02x", digest[i]);
    printf("\n");
    ret = send(lissoc, digest, sizeof(digest),0);
    if (ret<0){
        perror("Errore invio tipologia device");
        exit(-1);
    }
    else{
        printf("send successful\n");
    }
    printf("select an option: \n 1) login \n 2) register \n");
    char option [BUF_SIZE];
    scanf("%s", option);
    if (strcmp(option, "login") == 0){
        login(lissoc);
    }
    else if (strcmp(option, "register") == 0){
        //register();
    }
    else{
        printf("invalid option\n");
    }
}