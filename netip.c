#include <asm-generic/socket.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cjson/cJSON.h"
#include "netip.h"
#include "utils.h"

#define PACKED __attribute__((packed))

typedef struct netip_preabmle {
  uint8_t head;
  uint8_t version;
  uint16_t unused;
  uint32_t session;
  uint32_t sequence;
  uint8_t total;
  uint8_t cur;
  uint16_t msgid;
  uint32_t len_data;
  char data[];
} PACKED netip_preabmle_t;

#define MAX_UDP_PACKET_SIZE 0xFFFF

typedef union netip_pkt {
  char buf[1024];
  netip_preabmle_t header;
} netip_pkt_t;

#define NETIP_HSIZE sizeof(netip_preabmle_t)
#define NETIP_MAX_JSON sizeof(resp) - NETIP_HSIZE - 1

cJSON *json = NULL;
netip_pkt_t msg;
char *session_id;
char payload[1024];

char *netip_connect(int s, char *username, char *pass) {

  memset(&msg.header, 0, sizeof(msg.header));
  msg.header.head = 0xff;
  msg.header.msgid = LOGIN_REQ2;
  sprintf(payload,
          "{\"EncryptType\": \"MD5\", \"LoginType\": \"DVRIP-Web\", "
          "\"PassWord\": \"%s\", \"UserName\": \"%s\"}\n",
          pass, username);
  printf(">>> Login: %s", payload);

  strcpy(msg.header.data, payload);
  msg.header.len_data = sizeof(payload);

  if (send(s, &msg, sizeof(payload) + NETIP_HSIZE, 0) < 0) {
    goto quit;
  }

  if (recv(s, &msg, sizeof(msg), 0) <= NETIP_HSIZE) {
    goto quit;
  }

  json = cJSON_Parse(msg.header.data);
  if (!json) {
    const char *error_ptr = cJSON_GetErrorPtr();
    if (error_ptr != NULL) {
      fprintf(stderr, "Error before: %s\n", error_ptr);
    }
    goto quit;
  }

  session_id = get_json_strval(json, "SessionID", "");
  return session_id;

quit:
  return "null";
}

char *netip_req(int s, int op) {

  memset(&msg.header, 0, sizeof(msg.header));
  msg.header.head = 0xff;
  msg.header.msgid = op;

  printf(">>> Payload: %s\n", payload);

  strcpy(msg.header.data, payload);
  msg.header.len_data = sizeof(payload);

  if (send(s, &msg, sizeof(payload) + NETIP_HSIZE, 0) < 0) {
    goto quit;
  }
  if (recv(s, &msg, sizeof(msg), 0) <= NETIP_HSIZE) {
    goto quit;
  }
  printf(">>> Resp: %s\n", msg.header.data);
  return msg.header.data;

quit:
  printf("error\n");
  return "c";
}

char *read_file(char *filename) {
  char *buffer = 0;
  long length;
  FILE *f = fopen(filename, "rb");

  if (f) {
    fseek(f, 0, SEEK_END);
    length = ftell(f);
    fseek(f, 0, SEEK_SET);
    buffer = malloc(length);
    if (buffer) {
      fread(buffer, 1, length, f);
    }
    fclose(f);
  }

  if (buffer)
    return buffer;
}

int main() {
  const char *host_ip = "172.16.1.142";
  const int netip_port = 34567;

  char *username = "admin";
  char *pass = "QyZfVmgd";

  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s == -1)
    return false;

  struct sockaddr_in srv;
  srv.sin_addr.s_addr = inet_addr(host_ip);
  srv.sin_family = AF_INET;
  srv.sin_port = htons(netip_port);

  const int flags = fcntl(s, F_GETFL, 0);
  fcntl(s, F_SETFL, flags | O_NONBLOCK | SO_REUSEADDR);
  (void)connect(s, (struct sockaddr *)&srv, sizeof(srv));

  fd_set fdset;
  FD_ZERO(&fdset);
  FD_SET(s, &fdset);
  struct timeval tv = {
      .tv_sec = 2, /* 2 second timeout */
  };

  if (select(s + 1, NULL, &fdset, NULL, &tv) != 1) {
    goto quit;
  }
  fcntl(s, F_SETFL, flags);

  printf("<<< SessionID: %s\n", netip_connect(s, username, pass));

  memset(payload, 0, sizeof(payload));

  sprintf(payload, "{\"Name\": \"SystemInfo\", \"SessionID\": \"%s\"}\n",
          session_id);

  json = cJSON_Parse(netip_req(s, SYSINFO_REQ));

  char *newpass = "tlJwpbo6";
  char *newuser = "viewer";

  sprintf(payload,
          "{\"EncryptType\": \"MD5\", \"NewPassWord\": \"%s\", \"PassWord\": "
          "\"%s\", \"SessionID\": \"%s\", \"UserName\": \"%s\"}",
          newpass, pass, session_id, newuser);
  // netip_req(s, MODIFYPASSWORD_REQ);

quit:
  if (json)
    cJSON_Delete(json);
  close(s);
}