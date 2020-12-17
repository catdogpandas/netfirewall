#include <arpa/inet.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
//#include <linux/inet.h>

#define NETLINK_TEST 17
#define MSG_LEN 256

char *default_data = "Netlink Test Default Data";

struct msg_to_kernel {
  struct nlmsghdr hdr;
  char data[MSG_LEN];
};

struct u_packet_info {
  struct nlmsghdr hdr;
  char msg[MSG_LEN];
};

struct filter_rule {
  unsigned int src_ip;
  unsigned int src_port;
  unsigned int dst_ip;
  unsigned int dst_port;
  unsigned int src_mask;
  unsigned int dst_mask;
  unsigned int protocol;
  unsigned int action;
  unsigned int record;
};

int main(int argc, char *argv[]) {
  char data[256] = {0};
  int dlen;
  struct sockaddr_nl local;
  struct sockaddr_nl kpeer;
  int skfd, ret, kpeerlen = sizeof(struct sockaddr_nl);
  struct nlmsghdr *message = NULL;
  struct u_packet_info info;
  char *retval = NULL;

  if (argc == 1) {
    //输出help
    printf("add: -a src_ip src_mask dst_ip dst_mask src_port dst_port protocol "
           "action log\n");
    printf("list: -l\n");
    printf("log: -log\n");
    printf("save: -s\n");
    printf("remove: -r id\n");
    return 0;
  }

  if (strcmp(argv[1], "-a") == 0) {
    struct filter_rule test;
    test.src_ip = inet_addr(argv[2]);
    test.src_mask = (unsigned int)atoi(argv[3]);
    test.dst_ip = inet_addr(argv[4]);
    test.dst_mask = (unsigned int)atoi(argv[5]);
    test.src_port = (unsigned int)atoi(argv[6]);
    test.dst_port = (unsigned int)atoi(argv[7]);
    test.protocol = (unsigned int)atoi(argv[8]);
    test.action = (unsigned int)atoi(argv[9]);
    test.record = (unsigned int)atoi(argv[10]);
    data[0] = 'a';
    memcpy(data + 1, &test, sizeof(test));
    dlen = sizeof(test) + 2;
  } else if (strcmp(argv[1], "-l") == 0) {
    data[0] = 'l';
    dlen = strlen(data) + 1;
  } else if (strcmp(argv[1], "-log") == 0) {
    data[0] = 'L';
    dlen = strlen(data) + 1;
  } else if (strcmp(argv[1], "-s") == 0) {
    data[0] = 'l';
    dlen = strlen(data) + 1;
  } else if (strcmp(argv[1], "-r") == 0) {
    data[0] = 'r';
    unsigned int a = atoi(argv[2]);
    sprintf(data + 1, "%u", a);
    dlen = sizeof(a) + 2;
  } else {
    return 0;
  }

  skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
  if (skfd < 0) {
    printf("can not create a netlink socket\n");
    return -1;
  }

  memset(&local, 0, sizeof(local));
  local.nl_family = AF_NETLINK;
  local.nl_pid = getpid();
  local.nl_groups = 0;
  if (bind(skfd, (struct sockaddr *)&local, sizeof(local)) != 0) {
    printf("bind() error\n");
    return -1;
  }
  memset(&kpeer, 0, sizeof(kpeer));
  kpeer.nl_family = AF_NETLINK;
  kpeer.nl_pid = 0;
  kpeer.nl_groups = 0;

  message = (struct nlmsghdr *)malloc(sizeof(struct msg_to_kernel));
  if (message == NULL) {
    printf("malloc() error\n");
    return -1;
  }

  memset(message, '\0', sizeof(struct nlmsghdr));
  message->nlmsg_len = NLMSG_SPACE(dlen);
  message->nlmsg_flags = 0;
  message->nlmsg_type = 0;
  message->nlmsg_seq = 0;
  message->nlmsg_pid = local.nl_pid;

  retval = memcpy(NLMSG_DATA(message), data, dlen - 1);

  printf("message sendto kernel, content: '%s', len: %d\n",
         (char *)NLMSG_DATA(message), message->nlmsg_len);
  ret = sendto(skfd, message, message->nlmsg_len, 0, (struct sockaddr *)&kpeer,
               sizeof(kpeer));
  if (!ret) {
    perror("sendto:");
    exit(-1);
  }
  if (strcmp(argv[1], "-a") == 0) {
    ret = recvfrom(skfd, &info, sizeof(struct u_packet_info), 0,
                   (struct sockaddr *)&kpeer, &kpeerlen);
    if (!ret) {
      perror("recvfrom:");
      exit(-1);
    }
    if (strcmp((char *)info.msg, "end") == 0) {
      printf("END!\n");
    } else {
      printf("ERROR\n");
    }
  } else if (strcmp(argv[1], "-l") == 0) {
    while (1) {
      ret = recvfrom(skfd, &info, sizeof(struct u_packet_info), 0,
                     (struct sockaddr *)&kpeer, &kpeerlen);
      if (!ret) {
        perror("recvfrom:");
        exit(-1);
      }
      if (strcmp((char *)info.msg, "end") == 0) {
        printf("END!\n");
        break;
      }
      int k;
      memcpy(&k, info.msg, sizeof(k));
      struct filter_rule test;
      memcpy(&test, (char *)info.msg + sizeof(k), sizeof(test));
      printf("id:%d src_ip:%x src_mask:%d src_port:%d dst_ip:%x dst_mask:%d "
             "dst_port:%d protocol:%d action:%d log:%d\n",
             k, test.src_ip, test.src_mask, test.src_port, test.dst_ip,
             test.dst_mask, test.dst_port, test.protocol, test.action,
             test.record);
    }
  } else if (strcmp(argv[1], "-log") == 0) {
    data[0] = 'L';
    dlen = strlen(data) + 1;
  } else if (strcmp(argv[1], "-s") == 0) {
    while (1) {
      ret = recvfrom(skfd, &info, sizeof(struct u_packet_info), 0,
                     (struct sockaddr *)&kpeer, &kpeerlen);
      if (!ret) {
        perror("recvfrom:");
        exit(-1);
      }
      if (strcmp((char *)info.msg, "end") == 0) {
        printf("END!\n");
        break;
      }
      int k;
      memcpy(&k, info.msg, sizeof(k));
      struct filter_rule test;
      memcpy(&test, (char *)info.msg + sizeof(k), sizeof(test));
      printf("id:%d src_ip:%x src_mask:%d src_port:%d dst_ip:%x dst_mask:%d "
             "dst_port:%d protocol:%d action:%d log:%d\n",
             k, test.src_ip, test.src_mask, test.src_port, test.dst_ip,
             test.dst_mask, test.dst_port, test.protocol, test.action,
             test.record);
    }
  } else if (strcmp(argv[1], "-r") == 0) {
    data[0] = 'r';
    unsigned int a = atoi(argv[2]);
    sprintf(data + 1, "%u", a);
    dlen = sizeof(a) + 2;
  } else {
    return 0;
  }

  close(skfd);
  return 0;
}
