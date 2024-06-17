#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define AES_KEY_LEN EVP_MD_size(EVP_sha256())
#define SHARED_SECRET_LEN 513

typedef struct clientData{
   char username[USERNAME_LEN];
   char email[EMAIL_LEN];
   unsigned char* hashedpsw;
   unsigned char* salt;
   bool islogged;
} ClientData;

typedef struct clientNode{
   int clientfd;
   int status; // handshake status code || logged in TBD
   unsigned char* encrypted_data;
   unsigned char* sessionKey;
   struct clientNode* next;
} ClientNode;

typedef struct clientList{
   ClientNode* head;
   ClientNode* tail;
} ClientList;

ClientList* create_clientlist() {
    ClientList* list = (ClientList*)malloc(sizeof(ClientList));
    if (!list) {
        perror("Failed to allocate memory for list");
        exit(EXIT_FAILURE);
    }
    list->head = NULL;
    list->tail = NULL;
    return list;
}

int addclient(ClientList* list, int fd, int s, unsigned char* key){
   if(list == NULL){
		perror("list uninitialized.");
		return -1;
	}

	ClientNode* toadd = (ClientNode*)malloc(sizeof(ClientNode));
    if (!toadd) {
      perror("Failed to allocate memory for new node");
      return -1;
   }
	toadd->clientfd = fd;
   toadd->status = s;
   toadd->sessionKey = key;
	toadd->next = NULL;

	if(list->head == NULL || list->tail == NULL){
		list->head = list->tail = (ClientNode*)toadd;
	}
	else{
		list->tail->next = (ClientNode*)toadd;
		list->tail = (ClientNode*)toadd;
	}
	return 0;
}

int removeclient(ClientList* list, int fd){
   if (list == NULL){
		perror("list uninitialized.");
		return -1;
	}

   if (list->head == NULL){
		perror("list is empty.");
		return -1;
	}

   ClientNode* temp = list->head;
   ClientNode* prev = NULL;

   if (temp->clientfd == fd){
      list->head = temp->next;
      if (list->head == NULL){
         list->tail = NULL;
      }
      free(temp);
      return 0;
   }

   while (temp != NULL && temp->clientfd != fd){
      prev = temp;
      temp = temp->next;
   }

   if (temp == NULL) {
      perror("fd isn't in the list.");
      return -1;
   }
   prev->next = temp->next;

   if (temp->next == NULL){
      list->tail = prev;
   }
   free(temp);
   return 0;
}

void printlist(ClientList* list) {
    ClientNode* temp = list->head;
    while (temp != NULL) {
        printf("%d->", temp->clientfd);
        temp = temp->next;
    }
    printf("NULL\n");
}
/*
int main(void) {
    ClientList* list = createlist();

    addclient(list, 10, 0);
    addclient(list, 20, 0);
    addclient(list, 30, 0);
    addclient(list, 40, 0);
    printlist(list);

    removeclient(list, 20);
    printlist(list);

    removeclient(list, 40);
    printlist(list);

    return 0;
}
*/