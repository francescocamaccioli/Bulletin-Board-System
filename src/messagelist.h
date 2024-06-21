#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

typedef struct message{
   int mid;
   char author[USERNAME_LEN];
   char title[TITLE_LEN];
   char body[BODY_LEN];
   struct message* next;
} Message;
typedef struct Message* MessageList;

MessageList create_messagelist() {
    MessageList* list = (MessageList*)malloc(sizeof(MessageList));
    if (!list) {
        perror("Failed to allocate memory for list");
        exit(EXIT_FAILURE);
    }
    list = NULL;
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
void insert_message(MessageList* list, Message* toinsert) {
    if (!list || !toinsert) {
        return;
    }
    toinsert->next = list;
    list = toinsert;
}

MessageList* get_last_n_messages(MessageList* list, int n) {
    MessageList* last_n_messages = create_messagelist();
    Message* current = list;
    while (current && n > 0) {
        insert_message(last_n_messages, current);
        current = current->next;
        n--;
    }
    return last_n_messages;
}

void free_messagelist(MessageList* list) {
    if (!list) {
        return;
    }
    Message* current = list;
    while (current) {
        Message* next = current->next;
        free(current);
        current = next;
    }
    free(list);
}