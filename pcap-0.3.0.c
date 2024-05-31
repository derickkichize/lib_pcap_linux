#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

void
print_hex_dump (const u_char* data, size_t length)
{
  for (size_t i = 0; i < length; i += 16)
    {
      printf("%08zX ", i);

      size_t j;
      for (j = i; j < i + 16 && j < length; ++j)
	{
	  printf("%02X ", data[j]);
	  if (j % 8 == 7) printf (" ");
	}
      for (; j < i + 16; ++j)
	{
	  printf("    ");
	  if (j % 8 == 7) printf (" ");
	}

      printf(" |");

      for (j = i; j < i + 16 && j < length; ++j)
	{
	  if (data[j] >= 32 && data[j] <= 126)
	    printf("%c", data[j]);
	  else
	    printf(".");
	}
      printf("|\n");
    }
}


void
print_udp_flags (struct udphdr* udp_header)
{
  printf ("UDP checksum: <%04x>\n",udp_header->uh_sum);
}

void
print_tcp_flags (struct tcphdr* tcp_header)
{
  if (tcp_header->th_flags & TH_SYN)
    printf("<SYN> pkg\n");
  
  if (tcp_header->th_flags & TH_ACK)
    printf("<ACK> pkg\n");

  if (tcp_header->th_flags & TH_FIN)
    printf("<FIN> pkg\n");
  
  if (tcp_header->th_flags & TH_PUSH)
    printf("<PSH> pkg\n");
  
  if (tcp_header->th_flags & TH_URG)
    printf("<URG> pkg.\n");
  
  if (tcp_header->th_flags & TH_RST)
    printf("<RST> pkg\n");
}

void
print_udp_payload (const u_char* packet,
	const struct pcap_pkthdr* header,
	size_t iphdr_len, size_t udphdr_len)
{
  size_t payload_len = header->len - iphdr_len - udphdr_len;
  const u_char* payload = packet + iphdr_len + udphdr_len;

  if (payload_len > 0)
    {
      printf("UDP payload:\n");
      print_hex_dump  (payload, payload_len);
      printf ("\n");
    }
}
void
print_tcp_payload(const u_char* packet,
	const struct pcap_pkthdr* header,
	size_t iphdr_len, size_t tcphdr_len)
{
  size_t payload_len    = header->len - iphdr_len - tcphdr_len;
  const u_char* payload = packet + iphdr_len + tcphdr_len;

  if (payload_len > 0)
    {
      printf("TCP payload:\n");
      print_hex_dump  (payload, payload_len);
      printf ("\n");
    }
}


void
packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
  struct ether_header* eth_header;
  struct ip* ip_header;
  struct tcphdr* tcp_header;
  struct udphdr* udp_header;
  
  size_t iphdr_len, tcphdr_len, udphdr_len;

  eth_header = (struct ether_header*)packet;

  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
    {
      ip_header = (struct ip*)(packet + sizeof(struct ether_header));
      iphdr_len = ip_header->ip_hl * 4;

      if (ip_header->ip_p == IPPROTO_TCP)
	{
	  tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + iphdr_len);
	  tcphdr_len = tcp_header->th_off * 4;
	  
	  printf("Packet received - size: %d bytes\n", header->len);
	  
	  printf("DST: <%s> DST_PORT: `%d'\n",
		 inet_ntoa(ip_header->ip_dst),
		 ntohs(tcp_header->th_dport));

	  printf("SRC: <%s> SRC_PORT: `%d'\n",
		 inet_ntoa(ip_header->ip_src),
		 ntohs(tcp_header->th_sport));
		 
	  print_tcp_flags   (tcp_header);
	  print_tcp_payload (packet, header, iphdr_len, tcphdr_len);
	}
      else if (ip_header->ip_p == IPPROTO_UDP)
	{
	  udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + iphdr_len);
	  udphdr_len = sizeof(struct udphdr);

	  printf("Packet received - size: %d bytes\n", header->len);
	  
	  printf("DST: <%s> DST_PORT: `%d'\n",
		 inet_ntoa(ip_header->ip_dst),
		 ntohs(udp_header->uh_dport));

	  printf("SRC: <%s> SRC_PORT: `%d'\n",
		 inet_ntoa(ip_header->ip_src),
		 ntohs(udp_header->uh_sport));

	  print_udp_flags (udp_header);
	  print_udp_payload (packet, header, iphdr_len, udphdr_len);
	}
    }
  

}

#define INET_DEVICE "wlp3s0"
int
main (void)
{
  pcap_t* handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  handle = pcap_open_live(INET_DEVICE, BUFSIZ, 1, 1000, errbuf);

  if (handle == NULL)
    {
      fprintf(stderr, "Error while opening device for capture %s\n", errbuf);
      return -1;
    }

  pcap_loop (handle, 0, packet_handler, NULL);
  pcap_close(handle);

  return 0;
} 
