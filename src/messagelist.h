#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

typedef struct message{
   int mid;
   int ct_len;
   char author[USERNAME_LEN];
   char title[TITLE_LEN];
   char body[BODY_LEN];
   struct message* next;
} Message;
typedef struct Message* MessageList;


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
    printf("mid: %d\n", message->mid);
    printf("ct_len: %d\n", message->ct_len);
    printf("author: %s\n", message->author);
    printf("title: %s\n", message->title);
    printf("body: \n");
    for (int i = 0; i < message->ct_len; i++){
        printf("%02x", message->body[i]);
    }
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

void get_last_n_messages(MessageList list, const char* author, int n, char* buffer, size_t buffer_size) {
    Message* current = list;
    Message* author_messages[n];
    int count = 0;

    // Initialize author_messages array to NULL
    for (int i = 0; i < n; i++) {
        author_messages[i] = NULL;
    }

    // Traverse the list and collect messages from the specified author
    while (current != NULL) {
        if (strcmp(current->author, author) == 0) {
            if (count < n) {
                author_messages[count] = current;
                count++;
            } else {
                for (int i = 0; i < n - 1; i++) {
                    author_messages[i] = author_messages[i + 1];
                }
                author_messages[n - 1] = current;
            }
        }
        current = current->next;
    }

    // Create the output string within the buffer
    buffer[0] = '\0';
    for (int i = 0; i < count; i++) {
        char temp[256]; // Temporary buffer for each message
        snprintf(temp, sizeof(temp), "Message id: %d\nTitle: %s\n\n",
                 author_messages[i]->mid, author_messages[i]->title);
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
        printf("Creation Time: %d\n", current->ct_len);
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