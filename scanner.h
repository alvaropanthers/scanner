#include <stdbool.h>

#define PATH_LENGTH 50
#define AUTH_LOG_DEFAULT_PATH "/var/log/auth.log"
#define MAX_LINE_SIZE 1000
#define SSH_DEF "sshd"
#define MAX_WORDS 16
#define MAX_TO_LOG 1000
#define MAX_USERS_TO_LOG 100

#define PORT_SIZE 20
#define USER_SIZE 100
#define IP_SIZE 50
#define TYPE_SIZE 10

typedef struct user{
  char userName[USER_SIZE];
  char port[PORT_SIZE];
}user_t;

typedef struct log_t{
  int attempts;
  int pid;
  char type[TYPE_SIZE];
  char msg[MAX_LINE_SIZE];
  char ip[IP_SIZE];
  bool printed;
  user_t users[MAX_USERS_TO_LOG];
  int usersCount;
}log_t;


char* strext(char* buffer, char delstart, char delstop);
int extract_pid(char* buffer);
void log_attempt(int pid, char* user, char* ip, char* port);
void extract_words(char* msg, bool root);
void parse_file(char* fileName);
void print_log();
