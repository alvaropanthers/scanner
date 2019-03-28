#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "scanner.h"

log_t logStruct[MAX_TO_LOG];
int currentLogged = 0;

int main(int argc, char** args){
  if(argc > 1)
    parse_file(args[1]);
  else
    parse_file(NULL);

  print_log();

  return 0;
}

void print_log(){
  int x;
  for(x = 0; x < currentLogged; ++x){
    if((logStruct[x].printed == false)){
      printf("PID:\t%d\nIP:\t%s\nATTEMPTS:\t%d\nUSERS_TRIED:\t%d\n", 
      logStruct[x].pid, logStruct[x].ip, logStruct[x].attempts, logStruct[x].usersCount);
      
      printf("USERNAME_ATTEMPTS:");
      int y;
      for(y = 0; y < logStruct[x].usersCount; ++y){
        printf("%s(port: %s)", logStruct[x].users[y].userName, logStruct[x].users[y].port);
        if((y + 1) < logStruct[x].usersCount)
          printf(", ");
      }

      if(y > 0)
	      printf("\n");

      printf("\n");
      logStruct[x].printed = true;
    }
  }
  
    printf("%d records listed\n", x);

}

char* strext(char* buffer, char delstart, char delstop){
  char* tmp = malloc(MAX_CHARS * sizeof(char));
  int found = false;
  int counter = 0;
  for(int x = 1; x < strlen(buffer); ++x){
    if(buffer[x - 1] == delstart)
      found = true;
    else if(buffer[x] == delstop)
      found = false;

    if(found){
      tmp[counter] = buffer[x];
      ++counter;
    }
  }

  return tmp;
}

int extract_pid(char* buffer){
  char* tmp = strext(buffer, '[', ']');
  int pid = atoi(tmp);
  free(tmp);
  return  pid;
}

void log_attempt(int pid, char* user, char* ip, char* port){
  if(currentLogged < MAX_TO_LOG){
    for(int x = 0; x < currentLogged; ++x){
      if(strcmp(logStruct[x].ip, ip) == 0){
        ++(logStruct[x].attempts);

        bool userFound = false;
        for(int y = 0; y < logStruct[x].usersCount; ++y)
          if(strcmp(logStruct[x].users[y].userName, user) == 0)
            userFound = true;

        if(!userFound){
          int usCount = logStruct[x].usersCount;
          if(usCount < MAX_USERS_TO_LOG){
            strcpy(logStruct[x].users[usCount].userName, user);
            strcpy(logStruct[x].users[usCount].port, port);
            ++(logStruct[x].usersCount);
          }
        }
	
	      return;
      }
    }

    logStruct[currentLogged].pid = pid;
    strcpy(logStruct[currentLogged].users[logStruct[currentLogged].usersCount].userName, user);
    strcpy(logStruct[currentLogged].users[logStruct[currentLogged].usersCount].port, port);
    strcpy(logStruct[currentLogged].ip, ip);
    logStruct[currentLogged].attempts = 1;
    logStruct[currentLogged].printed = false;
    ++(logStruct[currentLogged].usersCount);
    ++currentLogged;
  }
  
  return;
}

void extract_words(char* msg, bool root){
  char* words[MAX_WORDS];

  int counter = 0;
  words[counter] = strtok(msg, " ");
  char* tmp;
  while((tmp = strtok(NULL, " ")) && counter < MAX_WORDS){
    ++counter;
    words[counter] = tmp;
  }

  int pid;
  char user[100], ip[100], port[100];
  if(counter == (MAX_WORDS - 1)){
    for(int x = 0; x < MAX_WORDS; ++x)
      if(((strcmp(words[x], "user") == 0) && !root) || ((strcmp(words[x], "for") == 0) && root))
        if(root)
          strcpy(user, "root");
        else
          strcpy(user, words[x + 1]); 
        else if(strcmp(words[x], "from") == 0)
          strcpy(ip, words[x + 1]); 
        else if(strcmp(words[x], "port") == 0)
          strcpy(port, words[x + 1]);
        else if(strstr(words[x], "sshd"))
          pid = extract_pid(words[x]);
  }

  log_attempt(pid, user, ip, port);
}

void parse_file(char* fileName){
  FILE* file;
  if(fileName == NULL)
    file = fopen(AUTH_LOG_DEFAULT_PATH, "r");
  else
    file = fopen(fileName, "r");

  if(file == NULL){
    fprintf(stderr, "Error: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  char tmp[MAX_LINE_SIZE];
  //fgets is getting a new line at a time
  while(fgets(tmp, MAX_LINE_SIZE, file)){
    if(strstr(tmp, SSH_DEF) && strstr(tmp, "Failed") && strstr(tmp, "root"))
      extract_words(tmp, true);
    else if(strstr(tmp, SSH_DEF) && strstr(tmp, "Failed"))
      extract_words(tmp, false);
  }

  fclose(file);
}
