#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
 
typedef struct {
uint8_t addr[6];
} Mac;
 
struct EthHdr {
Mac dmac;
Mac smac;
uint16_t type;
};
 
struct IpHdr {
uint8_t vhl;
uint8_t tos;
uint16_t len;
uint16_t id;
uint16_t off;
uint8_t ttl;
uint8_t proto;
uint16_t sum;
uint32_t sip;
uint32_t dip;
};
 
struct TcpHdr {
uint16_t sport;
uint16_t dport;
uint32_t seq;
uint32_t ack;
uint8_t off;
uint8_t flags;
uint16_t win;
uint16_t sum;
uint16_t urp;
};
 
struct PseudoHdr {
uint32_t sip;
uint32_t dip;
uint8_t zero;
uint8_t proto;
uint16_t tcp_len;
};
 
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_ACK 0x10
#define ETH_TYPE_IP 0x0800
#define IP_PROTO_TCP 6
 
pcap_t* handle;
char* pattern;
uint8_t my_mac[6];
int rawSd = -1;
 
uint16_t checksum(void* data, int len) {
uint32_t sum = 0;
uint16_t* ptr = (uint16_t*)data;
while (len > 1) {
sum += *ptr++;
len -= 2;
}
if (len == 1)
sum += *(uint8_t*)ptr;
sum = (sum >> 16) + (sum & 0xffff);
sum += (sum >> 16);
return ~sum;
}
 
void get_my_mac(const char* interface) {
int sock = socket(AF_INET, SOCK_DGRAM, 0);
struct ifreq ifr;
strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
ioctl(sock, SIOCGIFHWADDR, &ifr);
memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
close(sock);
}
 
void send_backward(const u_char* org_packet, uint16_t data_size) {
char* redirect = (char*)"HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n";
int redirect_len = strlen(redirect);
 
int buf_size = sizeof(struct EthHdr) + sizeof(struct IpHdr) + sizeof(struct TcpHdr) + redirect_len;
uint8_t buf[buf_size];
memset(buf, 0, buf_size);
 
struct EthHdr* org_eth = (struct EthHdr*)org_packet;
struct IpHdr* org_ip = (struct IpHdr*)(org_packet + sizeof(struct EthHdr));
struct TcpHdr* org_tcp = (struct TcpHdr*)(org_packet + sizeof(struct EthHdr) + sizeof(struct IpHdr));
 
struct EthHdr* new_eth = (struct EthHdr*)buf;
struct IpHdr* new_ip = (struct IpHdr*)(buf + sizeof(struct EthHdr));
struct TcpHdr* new_tcp = (struct TcpHdr*)(buf + sizeof(struct EthHdr) + sizeof(struct IpHdr));
uint8_t* new_data = buf + sizeof(struct EthHdr) + sizeof(struct IpHdr) + sizeof(struct TcpHdr);
 
memcpy(new_eth->dmac.addr, org_eth->smac.addr, 6);
memcpy(new_eth->smac.addr, my_mac, 6);
new_eth->type = org_eth->type;
 
new_ip->vhl = org_ip->vhl;
new_ip->tos = 0;
new_ip->len = htons(sizeof(struct IpHdr) + sizeof(struct TcpHdr) + redirect_len);
new_ip->id = htons(rand() & 0xFFFF);
new_ip->off = 0;
new_ip->ttl = 128;
new_ip->proto = IP_PROTO_TCP;
new_ip->sum = 0;
new_ip->sip = org_ip->dip;
new_ip->dip = org_ip->sip;
 
new_tcp->sport = org_tcp->dport;
new_tcp->dport = org_tcp->sport;
new_tcp->seq = org_tcp->ack;
new_tcp->ack = htonl(ntohl(org_tcp->seq) + data_size);
new_tcp->off = (sizeof(struct TcpHdr) / 4) << 4;
new_tcp->flags = TH_FIN | TH_ACK;
new_tcp->win = org_tcp->win;
new_tcp->sum = 0;
new_tcp->urp = 0;
 
memcpy(new_data, redirect, redirect_len);
 
new_ip->sum = checksum(new_ip, sizeof(struct IpHdr));
 
struct PseudoHdr pseudo;
pseudo.sip = new_ip->sip;
pseudo.dip = new_ip->dip;
pseudo.zero = 0;
pseudo.proto = IP_PROTO_TCP;
pseudo.tcp_len = htons(sizeof(struct TcpHdr) + redirect_len);
 
int tcp_buf_size = sizeof(struct PseudoHdr) + sizeof(struct TcpHdr) + redirect_len;
uint8_t tcp_buf[tcp_buf_size];
memcpy(tcp_buf, &pseudo, sizeof(struct PseudoHdr));
memcpy(tcp_buf + sizeof(struct PseudoHdr), new_tcp, sizeof(struct TcpHdr) + redirect_len);
new_tcp->sum = checksum(tcp_buf, tcp_buf_size);
 
struct sockaddr_in dest;
dest.sin_family = AF_INET;
dest.sin_port = new_tcp->dport;
dest.sin_addr.s_addr = new_ip->dip;
 
sendto(rawSd,
buf + sizeof(struct EthHdr),
buf_size - sizeof(struct EthHdr),
0,
(struct sockaddr*)&dest,
sizeof(dest));
 
printf("Backward FIN 전송 완료!\n");
}
 
void send_forward(const u_char* org_packet, uint16_t data_size) {
int buf_size = sizeof(struct EthHdr) + sizeof(struct IpHdr) + sizeof(struct TcpHdr);
uint8_t buf[buf_size];
memset(buf, 0, buf_size);
 
struct EthHdr* org_eth = (struct EthHdr*)org_packet;
struct IpHdr* org_ip = (struct IpHdr*)(org_packet + sizeof(struct EthHdr));
struct TcpHdr* org_tcp = (struct TcpHdr*)(org_packet + sizeof(struct EthHdr) + sizeof(struct IpHdr));
 
struct EthHdr* new_eth = (struct EthHdr*)buf;
struct IpHdr* new_ip = (struct IpHdr*)(buf + sizeof(struct EthHdr));
struct TcpHdr* new_tcp = (struct TcpHdr*)(buf + sizeof(struct EthHdr) + sizeof(struct IpHdr));
 
memcpy(new_eth->dmac.addr, org_eth->dmac.addr, 6);
memcpy(new_eth->smac.addr, my_mac, 6);
new_eth->type = org_eth->type;
 
new_ip->vhl = org_ip->vhl;
new_ip->tos = 0;
new_ip->len = htons(sizeof(struct IpHdr) + sizeof(struct TcpHdr));
new_ip->id = htons(rand() & 0xFFFF);
new_ip->off = 0;
new_ip->ttl = org_ip->ttl;
new_ip->proto = IP_PROTO_TCP;
new_ip->sum = 0;
new_ip->sip = org_ip->sip;
new_ip->dip = org_ip->dip;
 
new_tcp->sport = org_tcp->sport;
new_tcp->dport = org_tcp->dport;
new_tcp->seq = htonl(ntohl(org_tcp->seq) + data_size);
new_tcp->ack = org_tcp->ack;
new_tcp->off = (sizeof(struct TcpHdr) / 4) << 4;
new_tcp->flags = TH_RST | TH_ACK;
new_tcp->win = org_tcp->win;
new_tcp->sum = 0;
new_tcp->urp = 0;
 
new_ip->sum = checksum(new_ip, sizeof(struct IpHdr));
 
struct PseudoHdr pseudo;
pseudo.sip = new_ip->sip;
pseudo.dip = new_ip->dip;
pseudo.zero = 0;
pseudo.proto = IP_PROTO_TCP;
pseudo.tcp_len = htons(sizeof(struct TcpHdr));
 
uint8_t tcp_buf[sizeof(struct PseudoHdr) + sizeof(struct TcpHdr)];
memcpy(tcp_buf, &pseudo, sizeof(struct PseudoHdr));
memcpy(tcp_buf + sizeof(struct PseudoHdr), new_tcp, sizeof(struct TcpHdr));
new_tcp->sum = checksum(tcp_buf, sizeof(tcp_buf));
 
if (pcap_sendpacket(handle, buf, buf_size) != 0)
printf("Forward 전송 실패: %s\n", pcap_geterr(handle));
else
printf("Forward RST 전송 완료!\n");
}
 
void callback(u_char* user,
const struct pcap_pkthdr* header,
const u_char* packet) {
 
struct EthHdr* eth = (struct EthHdr*)packet;
if (ntohs(eth->type) != ETH_TYPE_IP) return;
 
struct IpHdr* ip = (struct IpHdr*)(packet + sizeof(struct EthHdr));
if (ip->proto != IP_PROTO_TCP) return;
 
struct TcpHdr* tcp = (struct TcpHdr*)(packet + sizeof(struct EthHdr) + sizeof(struct IpHdr));
 
uint16_t data_size = ntohs(ip->len) - sizeof(struct IpHdr) - sizeof(struct TcpHdr);
if (data_size == 0) return;
 
uint8_t* data = (uint8_t*)tcp + sizeof(struct TcpHdr);
 
if (memmem(data, data_size, pattern, strlen(pattern)) == NULL) return;
 
printf("패턴 발견! 차단 시작!\n");
 
send_backward(packet, data_size);
send_forward(packet, data_size);
}
 
int main(int argc, char* argv[]) {
if (argc != 3) {
printf("사용법: %s <interface> <pattern>\n", argv[0]);
return 1;
}
 
char* interface = argv[1];
pattern = argv[2];
 
get_my_mac(interface);
 
rawSd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
if (rawSd < 0) {
perror("raw socket 생성 실패");
return 1;
}
int one = 1;
setsockopt(rawSd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
 
char errbuf[PCAP_ERRBUF_SIZE];
handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
if (handle == NULL) {
printf("pcap 열기 실패: %s\n", errbuf);
return 1;
}
 
printf("캡처 시작! interface=%s pattern=%s\n", interface, pattern);
pcap_loop(handle, 0, callback, (u_char*)interface);
 
close(rawSd);
pcap_close(handle);
return 0;
}
