#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

typedef struct message{
   int mid;
   char author[USERNAME_LEN]; // da lasciare in chiaro per non fare 1204321380 decrypt a stecca
   char title[TITLE_LEN]; // da encryptare con rsa priv key del server
   char body[BODY_LEN]; // da encryptare
   struct message* next;
} Message;

typedef struct messageList{
   Message* head;
   int size;
} MessageList;

MessageList* create_messagelist() {
    MessageList* list = (MessageList*)malloc(sizeof(MessageList));
    if (!list) {
        perror("Failed to allocate memory for list");
        exit(EXIT_FAILURE);
    }
    list->head = NULL;
    return list;
}

// implementing a head insert to keep messages ordered by creation time
int insert();