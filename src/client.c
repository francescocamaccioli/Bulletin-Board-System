#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define BUF_SIZE 4096
#define SURN_MAX_LEN 1024
#define DATE_LEN 10
#define SELECT_SIZE 128

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
    int code = 5;
    inet_pton(AF_INET, "127.0.0.1", &srv_addr.sin_addr);
    ret = connect(lissoc, (struct sockaddr*) &srv_addr, sizeof(srv_addr));
    if (ret < 0){
        perror("Errore nella connect \n");
        exit(-1);
    }
   uint16_t type = htons(code);
    ret = send(lissoc, (void*)&type, sizeof(uint16_t),0);
    if (ret<0){
        perror("Errore invio tipologia device");
        exit(-1);
    }
    else{
        printf("send successful\n");
    }
}