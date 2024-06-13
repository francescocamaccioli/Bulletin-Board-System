#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#define BUF_SIZE 4096
#define DATE_LEN 30
#define SURN_MAX_LEN 1024
#define DATE_LEN 30
#define SELECT_SIZE 128

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

/** Evita letture parziali
 *
 *   \retval -1   errore (errno settato)
 *   \retval  0   se durante la lettura da fd leggo EOF
 *   \retval size se termina con successo
 */
static inline int readn(long fd, void* buf, size_t size) {
    size_t left = size;
    int r;
    char* bufptr = (char*)buf;
    while (left > 0) {
        if ((r = read((int)fd, bufptr, left)) == -1) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return 0;   // EOF
        left -= r;
        bufptr += r;
    }
    return size;
}

/** Evita scritture parziali
 *
 *   \retval -1   errore (errno settato)
 *   \retval  0   se durante la scrittura la write ritorna 0
 *   \retval  1   se la scrittura termina con successo
 */
static inline int writen(long fd, void* buf, size_t size) {
    size_t left = size;
    int r;
    char* bufptr = (char*)buf;
    while (left > 0) {
        if ((r = write((int)fd, bufptr, left)) == -1) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return 0;
        left -= r;
        bufptr += r;
    }
    return 1;
}