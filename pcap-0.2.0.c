#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

void
packet_handle(u_char* args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ether_header* eth_header;
  struct ip* ip_header;
  struct tcphdr* tcp_header;
  struct udphdr* udp_header;
  char src_ip[INET_ADDRSTRLEN];
  char dst_ip[INET_ADDRSTRLEN];
  uint16_t src_port, dst_port;

  eth_header = (struct ether_header*) packet;

  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
    {
      ip_header = (struct ip*)(packet + sizeof(struct ether_header));

      inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

      printf("src addr %s\t - ",   src_ip);
      printf("dst addr %s\n", dst_ip);

      if (ip_header->ip_p == IPPROTO_TCP)
	{
	  tcp_header = (struct tcphdr*)(
		packet + sizeof(struct ether_header) +
		sizeof(struct ip));
	  
	  src_port = ntohs(tcp_header->th_sport);
	  dst_port = ntohs(tcp_header->th_dport);
	  
	  printf("src port %d\t - ", src_port);
	  printf("dst port %d\n", dst_port);
	}
      else if (ip_header->ip_p == IPPROTO_UDP)
	{
	  udp_header = (struct udphdr*)(
		packet + sizeof(struct ether_header) +
		sizeof(struct ip));
	  
	  src_port = ntohs(udp_header->uh_sport);
	  dst_port = ntohs(udp_header->uh_dport);
	  
	  printf("src port %d\t - ", src_port);
	  printf("dst port %d\n", dst_port);
	}
    }
  
  printf("Packet received - size: %d bytes\n", header->len);
}

int
main()
{
  pcap_t* handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  handle = pcap_open_live("wlp3s0", BUFSIZ, 1, 1000, errbuf);

  if (handle == NULL)
    {
      fprintf(stderr, "Error while opening device for capture %s\n", errbuf);
      return -1;
    }

  pcap_loop(handle, 0, packet_handle, NULL);

  pcap_close(handle);

  return 0;
}
