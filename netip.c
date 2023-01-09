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
#define NETIP_MAX_JSON sizeof(netip_pkt_t) - NETIP_HSIZE - 1

int netip_connect(int s, char *username, char *pass) {
  netip_pkt_t msg = {
      .header.head = 0xff,
      .header.msgid = LOGIN_REQ2,
  };

  int len = sprintf(msg.header.data,
                    "{\"EncryptType\": \"MD5\", \"LoginType\": \"DVRIP-Web\", "
                    "\"PassWord\": \"%s\", \"UserName\": \"%s\"}\n",
                    pass, username);
  printf(">>> Login: %s", msg.header.data);
  msg.header.len_data = len;

  if (send(s, &msg, len + NETIP_HSIZE, 0) < 0) {
    return -1;
  }

  if (recv(s, &msg, sizeof(msg), 0) <= NETIP_HSIZE) {
    return -1;
  }

  cJSON *json = cJSON_Parse(msg.header.data);
  if (!json) {
    const char *error_ptr = cJSON_GetErrorPtr();
    if (error_ptr != NULL) {
      fprintf(stderr, "Error before: %s\n", error_ptr);
    }
    return -1;
  }

  printf("'%s'\n", msg.header.data);

  const char *session_str = get_json_strval(json, "SessionID", "");
  int session_id = strtoul(session_str, NULL, 16);
  cJSON_Delete(json);
  return session_id;
}

cJSON *netip_req(int s, int op, const char *payload) {
  netip_pkt_t msg = {
      .header.head = 0xff,
      .header.msgid = op,
  };

  printf(">>> Payload: %s\n", payload);

  strcpy(msg.header.data, payload);
  msg.header.len_data = strlen(payload);

  if (send(s, &msg, msg.header.len_data + NETIP_HSIZE, 0) < 0) {
    goto quit;
  }
  if (recv(s, &msg, sizeof(msg), 0) <= NETIP_HSIZE) {
    goto quit;
  }
  printf(">>> Resp: %s\n", msg.header.data);
  cJSON *json = cJSON_Parse(msg.header.data);
  return json;

quit:
  printf("error\n");
  return NULL;
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

  if (!buffer)
    return NULL;

  return buffer;
}

int main() {
  cJSON *json = NULL;
  const char *host_ip = "10.216.128.125";
  const int netip_port = 34567;

  char *username = "admin";
  char *pass = "tlJwpbo6";

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

  int session_id = netip_connect(s, username, pass);
  if (session_id == -1) {
    printf("Connection failed\n");
    goto quit;
  }
  printf("<<< SessionID: %#x\n", session_id);

  char payload[1024] = {0};
  sprintf(payload, "{\"Name\": \"SystemInfo\", \"SessionID\": \"%#.8x\"}\n",
          session_id);

  json = netip_req(s, SYSINFO_REQ, payload);

  char *newpass = "tlJwpbo6";
  char *newuser = "viewer";

  sprintf(payload,
          "{\"EncryptType\": \"MD5\", \"NewPassWord\": \"%s\", \"PassWord\": "
          "\"%s\", \"SessionID\": \"%#.8x\", \"UserName\": \"%s\"}",
          newpass, pass, session_id, newuser);
  // netip_req(s, MODIFYPASSWORD_REQ, payload);

quit:
  if (json)
    cJSON_Delete(json);
  close(s);
}
