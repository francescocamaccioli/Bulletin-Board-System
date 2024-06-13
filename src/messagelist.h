#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

typedef struct message{
   int mid;
   char author[20];
   char title[30];
   char body[100];
   struct message* next;
} Message;

typedef struct messageList{
   Message* head;
   Message* tail;
} MessageList;