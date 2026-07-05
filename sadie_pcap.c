#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                      iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int  iph_len; //IP Packet length (data + header)
  unsigned short int  iph_ident; //Identification
  unsigned short int  iph_flag:3, //Fragmentation flags
                      iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int  iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct tcpheader {
  unsigned short int tcp_sport;   //Source port
  unsigned short int tcp_dport;   //Destination port
  unsigned int       tcp_seq;     //Sequence number
  unsigned int       tcp_ack;     //Acknowledgement number
  unsigned char      tcp_offx2;   //Data offset, upper 4 bits
  unsigned char      tcp_flags;
  unsigned short int tcp_win;     //Window size
  unsigned short int tcp_sum;     //Checksum
  unsigned short int tcp_urp;     //Urgent pointer
};
#define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type

    /* Ethernet Header 출력 */
    printf("Ethernet Header\n");
    printf("   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    struct ipheader * ip = (struct ipheader *)
                            (packet + sizeof(struct ethheader));

    printf("   From: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   To: %s\n", inet_ntoa(ip->iph_destip));

    /* determine protocol */
    switch(ip->iph_protocol) {
      case IPPROTO_TCP: {
        int ip_header_len = ip->iph_ihl * 4;
        struct tcpheader *tcp = (struct tcpheader *)
                                 ((u_char *)ip + ip_header_len);

        printf("   Protocol: TCP\n");
        printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
        printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));

        int tcp_header_len = TH_OFF(tcp) * 4;
        int total_header_len = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
        int http_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

        if (http_len > 0) {
          char *http_msg = (char *)(packet + total_header_len);
          printf("   HTTP Message:\n");
          for (int i = 0; i < http_len; i++) {
            printf("%c", http_msg[i]);
          }
          printf("\n");
        }
        return;
      }
      case IPPROTO_UDP:
        printf("   Protocol: UDP\n");
        return;
      case IPPROTO_ICMP:
        printf("   Protocol: ICMP\n");
        return;
      default:
        printf("   Protocol: others\n");
        return;
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name ens33
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) != 0) {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
