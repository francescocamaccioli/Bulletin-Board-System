#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/ioctl.h>

#define AES_KEY_LEN EVP_MD_size(EVP_sha256())
#define SHARED_SECRET_LEN 256

typedef struct clientNode{
   int clientfd;
   int hs; // 0: not handshaked, 1: handshaked
   int status; // 0: not logged in, 1: logged in
   int sessionKeyLen;
   int sharedSecretLen;
   char username[USERNAME_LEN];
   char email[EMAIL_LEN];
   char hashedpsw[HASH_SIZE];
   char salt[SALT_LEN];
   unsigned char sessionKey[HASH_SIZE+16];
   unsigned char sharedSecret[HASH_SIZE+16];
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

int addhs(ClientList* list, int fd, unsigned char* sharedsecret, int shslen, unsigned char* skey, int skeylen){
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
   toadd->status = 0;
   toadd->sharedSecretLen = shslen;
   toadd->sessionKeyLen = skeylen;
   toadd->hs = 1;
   toadd->next = NULL;
   memcpy(toadd->sharedSecret, sharedsecret, HASH_SIZE+16);
   memcpy(toadd->sessionKey, skey, AES_KEY_LEN+16);

   if(list->head == NULL || list->tail == NULL){
      list->head = list->tail = toadd;
   }
   else{
      list->tail->next = toadd;
      list->tail = toadd;
   }
   return 0;
}

// function that find the element in the list with the given fd
ClientNode* findclient(ClientList* list, int fd) {
    if (list == NULL) {
        perror("list uninitialized.");
        return NULL;
    }

    if (list->head == NULL) {
        perror("list is empty.");
        return NULL;
    }

    ClientNode* temp = list->head;

    while (temp != NULL) {
        if (temp->clientfd == fd) {
            return temp;
        }
        temp = temp->next;
    }
    return NULL;
}

// function to add missing information to the client node
int addinfo(ClientList* list, int fd, char* username, char* email, char* hashedpassword, char* salt){
   if(list == NULL){
      perror("list uninitialized.");
      return -1;
   }

   ClientNode* toadd = findclient(list, fd);
   if (!toadd) {
      perror("Client not found.");
      return -1;
   }
   strncpy(toadd->email, email, EMAIL_LEN);
   strncpy(toadd->username, username, USERNAME_LEN);
   strncpy(toadd->hashedpsw, hashedpassword, HASH_SIZE);
   strncpy(toadd->salt, salt, SALT_LEN);
   return 0;
}

int addclient(ClientList* list, int fd, int s, char* username, char* email, char* hashedpassword, char* salt, unsigned char* key){
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
   strncpy(toadd->email, email, sizeof(toadd->email) - 1);
   strncpy(toadd->username, username, sizeof(toadd->username) - 1);
   strncpy(toadd->hashedpsw, hashedpassword, sizeof(toadd->hashedpsw) - 1);
   strncpy(toadd->salt, salt, sizeof(toadd->salt) - 1);
   strncpy((unsigned char*)toadd->sessionKey, key, sizeof(toadd->sessionKey) - 1);
   toadd->next = NULL;

   if(list->head == NULL || list->tail == NULL){
      list->head = list->tail = toadd;
   }
   else{
      list->tail->next = toadd;
      list->tail = toadd;
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

int isin(ClientList* list, char* username){
   if (list == NULL){
      return -1;
   }

   if (list->head == NULL){
      return -1;
   }

   ClientNode* temp = list->head;

   while (temp != NULL){
      if (strcmp(temp->username, username) == 0){
         return 1;
      }
      temp = temp->next;
   }
   return -1;
}

int checkpwd(ClientNode* client, unsigned char* hashed_pwd){
   if (client == NULL || hashed_pwd == NULL){
      return 1;
   }

   ClientNode* temp = client;

   // retrieve user's salt and hash the hashed password with it
   unsigned char* salted_pwd = malloc(HASH_SIZE);
   compute_sha256_salted(hashed_pwd, strlen(hashed_pwd), salted_pwd, temp->salt);

   // compare the hashed password with the stored one
   if (memcmp(salted_pwd, temp->hashedpsw, HASH_SIZE) == 0){
      return 0;
   }
   return 1;
}

int isloggedin(ClientList* list, char* username){
   if (list == NULL || username == NULL){
      return -1;
   }

   if (list->head == NULL){
      return -1;
   }

   ClientNode* temp = list->head;

   while (temp != NULL){
      if (strcmp(temp->username, username) == 0){
         if (temp->status == 1){
            return 1;
         }
         else{
            return 0;
         }
      }
      temp = temp->next;
   }
   return 0;
}

void changestatus(ClientList* list, char* username, int s){
   if (list == NULL){
      return;
   }

   if (list->head == NULL){
      return;
   }

   ClientNode* temp = list->head;

   while (temp != NULL){
      if (strcmp(temp->username, username) == 0){
         temp->status = s;
         return;
      }
      temp = temp->next;
   }
}

char* getusername(ClientList* list, int fd){
   if (list == NULL){
      return NULL;
   }

   if (list->head == NULL){
      return NULL;
   }

   ClientNode* temp = list->head;

   while (temp != NULL){
      if (temp->clientfd == fd){
         return temp->username;
      }
      temp = temp->next;
   }
   return NULL;
}

void free_clientlist(ClientList* list) {
    if (!list) {
        return;
    }
    ClientNode* current = list->head;
    while (current) {
        ClientNode* next = current->next;
        free(current);
        current = next;
    }
    free(list);
}

void print_separator() {
   struct winsize w;
   ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
   int terminal_width = w.ws_col;
   int separator_length = terminal_width - 1;
   char separator[separator_length + 1];
   memset(separator, '-', separator_length);
   separator[separator_length] = '\0';
   puts(separator);
}

void printlist(ClientList* list) {
   ClientNode* temp = list->head;
   while (temp != NULL) {
      print_separator();
      printf("Client FD: %d\n", temp->clientfd);
      printf("Status: %d\n", temp->status);
      printf("Username: %s\n", temp->username);
      printf("Email: %s\n", temp->email);
      // printing hashed password as hex
      printf("Salted Hashed Password: ");
      for (int i = 0; i < HASH_SIZE; i++) {
         printf("%02x", temp->hashedpsw[i]);
      }
      printf("\n");
      printf("Salt: ");
      for (int i = 0; i < SALT_LEN; i++) {
         printf("%02x", temp->salt[i]);
      }
      printf("\n");
      printf("Shared Secret: ");
      for (int i = 0; i < HASH_SIZE; i++) {
         printf("%02x", temp->sharedSecret[i]);
      }
      // printing skey key as hex
      printf("skey Key: ");
      for (int i = 0; i < AES_KEY_LEN; i++) {
         printf("%02x", temp->sessionKey[i]);
      }
      printf("\n");
      temp = temp->next;
      print_separator();
   }
}
