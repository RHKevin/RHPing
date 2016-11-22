#include<stdio.h>
#include<signal.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>
#include<netdb.h>
#include<errno.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>
#include<sys/time.h>

#define PACKET_SIZE 4096
#define MAX_WAIT_TIME 1

int sockfd, datalen = 56;
int nsend = 0, nreceived = 0;

char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];

struct sockaddr_in dest_addr;
struct sockaddr_in from;
struct timeval tvrecv;

pid_t pid;
int error_no = -1;

double max_ping = 0;
double min_ping = 999999;
double sum_ping = 0;  // for avg calculation
double stddev_sum = 0; // for stddev calculation, represent sum of ping^2.

void statistics();
void timeout();
unsigned short checksum(unsigned short *, int);
int pack(int);
void send_packet(void);
void recv_packet(void);
int unpack(char *, int);
void tv_sub(struct timeval *,struct timeval *);
void pinger();
void ping_loop();

void statistics() {

  printf("\n--------------------PING statistics-------------------\n");
  printf("%d packets transmitted, %d received , %.2f%% packet loss\n", nsend, nreceived, ((double)nsend - nreceived) / nsend * 100);
  double avg_ping = sum_ping / nreceived;
  double stddev = sqrt(stddev_sum / nreceived - (avg_ping * avg_ping));
  printf("max/avg/min/stddev = %.3f/%.3f/%.3f/%.3f\n ms", max_ping, avg_ping, min_ping, stddev);
  close(sockfd);
  exit(0);
}

unsigned short checksum(unsigned short *addr, int len) {

  unsigned int sum = 0;
  unsigned short *w = addr;
  int count = len;

  while (count > 1) {
    sum += *w++;
    count -= 2;
  }

  if (count) {
    sum += *(unsigned short *)w;
  }

  while (sum >> 16) {
    sum = (sum >> 16) + (sum & 0xffff);
  }

  return (unsigned short)~sum;
}

int pack(int pack_no) {

  int packsize;
  struct icmp *icmp;
  struct timeval *tval;
  icmp = (struct icmp*)sendpacket;
  icmp->icmp_type = ICMP_ECHO;
  icmp->icmp_code = 0;
  icmp->icmp_cksum = 0;
  icmp->icmp_seq = htons(pack_no);
  icmp->icmp_id = pid;
  packsize = 8 + datalen;
  tval = (struct timeval  *)icmp->icmp_data;
  gettimeofday(tval, NULL);
  icmp->icmp_cksum = checksum((unsigned short *)icmp, packsize);

  return packsize;
}

void send_packet() {
  int packsize;
  nsend++;
  packsize = pack(nsend);
  if (sendto(sockfd, sendpacket, packsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
    perror("sendto error");
  }
}

void recv_packet() {

  int n, fromlen;
  fromlen = sizeof(from);
  if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, (struct sockaddr *)&from, (socklen_t *)&fromlen)) < 0) {
    if (errno == EINTR) {
      printf("recvfrom is interrupted\n");
      return;
    }
    if (errno == EAGAIN) {
      printf("Request timeout\n");
      error_no = errno;
      return;
    }
    perror("recvfrom error");
    return;
  }
  gettimeofday(&tvrecv, NULL);

  if (unpack(recvpacket, n) == -1)
    recv_packet();
  else nreceived++;
    /*
    ALL readers of the ICMP socket get a copy of ALL ICMP packets
    which arrive, once we got a wrong packet, we try to recv again.
    */

}

int unpack(char *buf, int len) {

  int iphdrlen;
  struct ip *ip;
  struct icmp *icmp;
  struct timeval *tvsend;
  double rtt;
  ip = (struct ip *)buf;
  iphdrlen = ip->ip_hl << 2; //skip ip head, ip_hl(head length) * 4 bytes.
  icmp = (struct icmp *)(buf + iphdrlen);
  len -= iphdrlen;
  if (len < 8) {
    printf("ICMP packet\'s length is less than 8\n");
    return -1;
  }

  if ((icmp->icmp_type == ICMP_ECHOREPLY && icmp->icmp_id == pid)) {
    tvsend = (struct timeval *)icmp->icmp_data;

      tv_sub (&tvrecv, tvsend);
      rtt = tvrecv.tv_sec * 1000 + tvrecv.tv_usec / 1000.0;
      printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%.3f ms\n",
                        len,
                        inet_ntoa(from.sin_addr),
                        htons(icmp->icmp_seq),
                        ip->ip_ttl,
                        rtt);

      if (rtt > max_ping) max_ping = rtt;
      if (rtt < min_ping) min_ping = rtt;
      sum_ping += rtt;
      stddev_sum += rtt * rtt;

      return 0;
    } else {
      return -1;
    }
}

void tv_sub(struct timeval *out,struct timeval *in) {

  if((out->tv_usec -= in->tv_usec) < 0)
  {
    --out->tv_sec;
    out->tv_usec += 1000000;
  }
  out->tv_sec -= in->tv_sec;
}

void pinger() {

  send_packet();
  recv_packet();
}

static volatile sig_atomic_t flag = 0;

void setflag(int whatever) {
  flag = 1;
}

void ping_loop() {

  struct sigaction act, oact;
  act.sa_handler = setflag;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;

  sigset_t zeroset;
  sigemptyset(&zeroset);

  sigaction(SIGALRM, &act, &oact);

  flag = 1;

  while ( 1 ) {
    if ( flag == 1 ) {
        alarm(1);
        flag = 0;
        pinger();
     }
    //else {
    //   while ( flag == 0 )
    //     sigsuspend(&zeroset);
    // }
    /*here the else segment can reduce the loop times of while to twice a ping round(when not timeout and no other signal occur),
    but it increase about 0.05ms round-trip time.*/
  }
}

int main(int argc, char *argv[]) {

  struct hostent *host;
  struct protoent *protocol;
  unsigned long inaddr = 0l;
  int size = 50 * 1024;

  if(argc < 2) {
    printf("usage:%s hostname/IP address\n",argv[0]);
    exit(1);
  }

  if((protocol = getprotobyname("icmp")) == NULL) {
    perror("getprotobyname");
    exit(1);
  }

  if((sockfd = socket(AF_INET,SOCK_RAW,protocol->p_proto)) < 0) {
    perror("socket error");
    exit(1);
  }

  pid = getpid();

  setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
  bzero(&dest_addr, sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;

  if ((inaddr = inet_addr(argv[1])) == INADDR_NONE) {
    if ((host = gethostbyname(argv[1])) == NULL) {
      perror("gethostbyname error");
      exit(1);
    }
    memcpy((char *)&dest_addr.sin_addr, host->h_addr, host->h_length);
  } else {
    memcpy( (char *)&dest_addr.sin_addr ,(char *)&inaddr, sizeof(inaddr));
  }

  pid = getpid();
  printf("PING %s(%s): %d bytes data in ICMP packets.\n", argv[1], inet_ntoa(dest_addr.sin_addr),datalen);

  struct sigaction act;
  sigemptyset(&act.sa_mask);
  sigaddset(&act.sa_mask, SIGALRM);
  act.sa_flags = 0;
  act.sa_handler = statistics;
  sigaction(SIGINT, &act, NULL);

  ping_loop();

  return 0;
}
