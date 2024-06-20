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
    list->size = 0;
    return list;
}

Message* create_message(int mid, char* author, char* title, char* body) {
    Message* message = (Message*)malloc(sizeof(Message));
    if (!message) {
        perror("Failed to allocate memory for message");
        exit(EXIT_FAILURE);
    }
    message->mid = mid;
    strcpy(message->author, author);
    strcpy(message->title, title);
    strcpy(message->body, body);
    message->next = NULL;
    return message;
}

// implementing a head insert to keep messages ordered by creation time
void insert_message(MessageList* list, Message* message) {
    if (!list || !message) {
        return;
    }
    message->next = list->head;
    list->head = message;
    list->size++;
}

MessageList* get_last_n_messages(MessageList* list, int n) {
    MessageList* last_n_messages = create_messagelist();
    Message* current = list->head;
    while (current && n > 0) {
        insert_message(last_n_messages, current);
        current = current->next;
        n--;
    }
    return last_n_messages;
}