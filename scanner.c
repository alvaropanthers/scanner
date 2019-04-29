#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "scanner.h"

log_t logStruct[MAX_TO_LOG];
int currentLogged = 0;

int main(int argc, char** args){
  
  if(argc > 1){
    parse_file(args[1]);
  }
  else{
    parse_file(NULL);
  }

  print_log();

  return 0;
}

void 
print_log(){
  int x;
  for(x = 0; x < currentLogged; ++x){
    if((logStruct[x].printed == false)){
      printf("IP:\t%s\nATTEMPTS:\t%d\nUSERS_TRIED:\t%d\n", 
      logStruct[x].ip, logStruct[x].attempts, logStruct[x].usersCount);
      
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

void 
log_attempt(char *user, char *ip, char *port){
  if(currentLogged < MAX_TO_LOG){
    for(int x = 0; x < currentLogged; ++x){
      if(strcmp(logStruct[x].ip, ip) == 0){
        ++(logStruct[x].attempts);

        bool userFound = false;
        for(int y = 0; y < logStruct[x].usersCount; ++y){
          if(strcmp(logStruct[x].users[y].userName, user) == 0){
            userFound = true;
          }
        }

        if(!userFound){
          int usCount = logStruct[x].usersCount;
          if(usCount < MAX_USERS_TO_LOG){
            strncpy(logStruct[x].users[usCount].userName, user, USER_SIZE);
            strncpy(logStruct[x].users[usCount].port, port, PORT_SIZE);
            ++(logStruct[x].usersCount);
          }
        }
	
	      return;
      }
    }

    strncpy(logStruct[currentLogged].users[logStruct[currentLogged].usersCount].userName, user, USER_SIZE);
    strncpy(logStruct[currentLogged].users[logStruct[currentLogged].usersCount].port, port, PORT_SIZE);
    strncpy(logStruct[currentLogged].ip, ip, IP_SIZE);
    logStruct[currentLogged].attempts = 1;
    logStruct[currentLogged].printed = false;
    ++(logStruct[currentLogged].usersCount);
    ++currentLogged;
  }
  
}

char **
break_line(char *line, int *counter, char *delimiter){
  *counter = 0;
  char **words = (char**)malloc(sizeof(char*) * MAX_WORDS);
  words[*counter] = strtok(line, delimiter);
  
  char* tmp;
  while((tmp = strtok(NULL, " ")) && *counter < MAX_WORDS){
    ++(*counter);
    words[*counter] = tmp;
  }

  //Size of words buffer
  *counter += 1;

  return words;
}

void 
extract_words(char *line, bool root){
  int counter = 0;
  char** words = break_line(line, &counter, " ");

  if(counter){
    int length = 0;
    char user[USER_SIZE], ip[IP_SIZE], port[PORT_SIZE];
    
    if(counter == MIN_WORDS){
      length = MIN_WORDS;
    }else if(counter == MAX_WORDS){
      length = MAX_WORDS;
    }
    
    for(int x = 0; x < length; ++x){
      if((length == MIN_WORDS && strcmp(words[x], "for") == 0) 
      || (length == MAX_WORDS && strcmp(words[x], "user") == 0)){
        strncpy(user, words[x + 1], USER_SIZE);
      }else if(strcmp(words[x], "from") == 0){
        strncpy(ip, words[x + 1], IP_SIZE);
      }else if(strcmp(words[x], "port") == 0){
        strncpy(port, words[x + 1], PORT_SIZE);
      }
    }
    
    log_attempt(user, ip, port);
  }

  free(words);
}

void 
parse_file(char* fileName)
{
  FILE* file;
  if(fileName == NULL){
    file = fopen(AUTH_LOG_DEFAULT_PATH, "r");
  }else{
    file = fopen(fileName, "r");
  }

  if(file == NULL){
    fprintf(stderr, "Error: %s\n", strerror(errno));
    exit(EXIT_FAILURE);
  }

  char tmp[MAX_LINE_SIZE];
  //fgets is getting a new line at a time
  while(fgets(tmp, MAX_LINE_SIZE, file)){
    if(strstr(tmp, SSH_DEF) && strstr(tmp, FAILED)){
      extract_words(tmp, false);
    }
  }

  fclose(file);
}