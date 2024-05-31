#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

void
packet_handler (
     u_char* user,
     const struct pcap_pkthdr *pkthdr,
     const u_char* packet)
{
  printf("Packet received - size: %d bytes\n", pkthdr->len);
}

void
__usage (const char* progname)
{
  printf ("Usage: %s <network interface>\n", progname);
  exit (1);
}

int
main (int argc, char*argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* pcap_handle;

  if (argc != 2)
    __usage(argv[0]);

  pcap_handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

  if (pcap_handle == NULL)
    {
      fprintf(stderr, "Error while opneing network adapter: %s\n", errbuf);
      return 1;
    }

  pcap_loop(pcap_handle, 0, packet_handler, NULL);

  pcap_close(pcap_handle);

  return 0;
}
