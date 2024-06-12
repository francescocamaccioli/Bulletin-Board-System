#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

typedef struct clientNode{
   int clientfd;
   int status; // idle, handshake...
   void* next;
} clientNode;

typedef struct clientList{
   clientNode* head;
   clientNode* tail;
} clientList;

clientList* createlist() {
    clientList* list = (clientList*)malloc(sizeof(clientList));
    if (!list) {
        perror("Failed to allocate memory for list");
        exit(EXIT_FAILURE);
    }
    list->head = NULL;
    list->tail = NULL;
    return list;
}

int addclient(clientList* list, int fd, int s){
   if(list == NULL){
		perror("list uninitialized.");
		return -1;
	}

	clientNode* toadd = (clientNode*)malloc(sizeof(clientNode));
    if (!toadd) {
      perror("Failed to allocate memory for new node");
      return -1;
   }
	toadd->clientfd = fd;
   toadd->status = s;
	toadd->next = NULL;

	if(list->head == NULL || list->tail == NULL){
		list->head = list->tail = (clientNode*)toadd;
	}
	else{
		list->tail->next = (clientNode*)toadd;
		list->tail = (clientNode*)toadd;
	}
	return 0;
}

int removeclient(clientList* list, int fd){
   if (list == NULL){
		perror("list uninitialized.");
		return -1;
	}

   if (list->head == NULL){
		perror("list is empty.");
		return -1;
	}

   clientNode* temp = list->head;
   clientNode* prev = NULL;

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

void printlist(clientList* list) {
    clientNode* temp = list->head;
    while (temp != NULL) {
        printf("%d->", temp->clientfd);
        temp = temp->next;
    }
    printf("NULL\n");
}
/*
int main(void) {
    clientList* list = createlist();

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