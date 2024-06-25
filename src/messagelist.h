#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "utils.h"

typedef struct message{
   int mid;
   int ct_len;
   char author[USERNAME_LEN];
   char title[TITLE_LEN];
   char body[BODY_LEN];
   struct message* next;
} Message;
typedef Message* MessageList;


Message* create_message(int mid, int ctlen, char* author, char* title, char* body) {
    Message* message = (Message*)malloc(sizeof(Message));
    if (!message) {
        perror("Failed to allocate memory for message");
        exit(EXIT_FAILURE);
    }
    message->mid = mid;
    message->ct_len = ctlen;
    strcpy(message->author, author);
    strcpy(message->title, title);
    strcpy(message->body, body);
    message->next = NULL;
    return message;

}

// function to insert the a message in the list head
void insert_message(MessageList* list, Message* message) {
    if (!list) {
        return;
    }
    message->next = *list;
    *list = message;
}

void getmessage(MessageList list, int mid, char* buffer, size_t buffer_size, unsigned char* key) {
    Message* current = list;
    while (current != NULL) {
        if (current->mid == mid) {
            // decrypt the body with AES256 ECB
            char decrypted_body[BODY_LEN];
            int decrypted_len;
            decrypt_message_AES256ECB((unsigned char*)current->body, (current->ct_len)+1, key, (unsigned char*)decrypted_body, &decrypted_len);
            snprintf(buffer, buffer_size, "Message id: %d\nTitle: %s\nAuthor: %s\nBody: %s\n\n", current->mid, current->title, current->author, decrypted_body);
            return;
        }
        current = current->next;
    }
    snprintf(buffer, buffer_size, "Message with id %d not found\n", mid);
}

void get_last_n_messages(MessageList list, int n, char* buffer, size_t buffer_size, unsigned char* key) {
    Message* current = list;
    Message* messages[n];
    int count = 0;

    // Initialize messages array to NULL
    for (int i = 0; i < n; i++) {
        messages[i] = NULL;
    }

    // Traverse the list and collect the first n messages
    while (current != NULL && count < n) {
        messages[count] = current;
        count++;
        current = current->next;
    }
    // Create the output string within the buffer
    buffer[0] = '\0';
    for (int i = 0; i < count; i++) {
        char temp[1028]; // Temporary buffer for each message
        // decrypt the body with AES256 ECB
        char decrypted_body[BODY_LEN];
        int decrypted_len;
        decrypt_message_AES256ECB((unsigned char*)messages[i]->body, (messages[i]->ct_len)+1, key, (unsigned char*)decrypted_body, &decrypted_len);
        snprintf(temp, sizeof(temp), "Message id: %d\nTitle: %s\nAuthor: %s\nBody: %s\n\n", messages[i]->mid, messages[i]->title, messages[i]->author, decrypted_body);
        if (strlen(buffer) + strlen(temp) + 1 > buffer_size) {
            // Prevent buffer overflow
            fprintf(stderr, "Buffer size exceeded\n");
            return;
        }
        strcat(buffer, temp);
    }
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

//function to print the message list
void print_messagelist(MessageList* list) {
    if (!list) {
        return;
    }
    Message* current = list;
    while (current) {
        printf("Message ID: %d\n", current->mid);
        printf("Author: %s\n", current->author);
        printf("Title: %s\n", current->title);
        printf("Body: ");
        for (int i = 0; i < current->ct_len; i++) {
            printf("%02x", current->body[i]);
        }
        printf("\n");
        current = current->next;
    }
}