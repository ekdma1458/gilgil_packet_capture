#include "printfpacket.h"

void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    libnet_ethernet_hdr* ethernet_hdr = (libnet_ethernet_hdr*)malloc(sizeof(libnet_ethernet_hdr));
    libnet_ipv4_hdr* ip_hdr = (libnet_ipv4_hdr*)malloc(sizeof(libnet_ipv4_hdr));
    libnet_tcp_hdr* tcp_hdr = (libnet_tcp_hdr*)malloc(sizeof(libnet_tcp_hdr));

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        printf("\r\n%u bytes captured\n", header->caplen);

        if(packetInsert(const_cast<u_char*>(packet), &ethernet_hdr, &ip_hdr, &tcp_hdr)){
            printfMacInfo(ethernet_hdr);
            printf_Ip_Port_Info(ip_hdr, tcp_hdr);
            printfTcpData(ip_hdr, tcp_hdr, packet);
        }
        /*
        if(my_ntohs(*(reinterpret_cast<const u_int16_t*>(packet+12))) == 0x0800){       //check ip
            if(reinterpret_cast<u_int8_t>(*(packet+23)) == 0x06){                       // check tcp
                printfMacInfo('S', packet+6);                                           // show Source Mac Address
                printfMacInfo('D', packet);                                             // show Des Mac Address
                printf_Ip_Port_Info('S', my_ntohd(*(reinterpret_cast<const u_int32_t*>(packet+24))), my_ntohs(*(reinterpret_cast<const u_int16_t*>(packet+34)))); //show Source IP & Port Info
                printf_Ip_Port_Info('D', my_ntohd(*(reinterpret_cast<const u_int32_t*>(packet+30))), my_ntohs(*(reinterpret_cast<const u_int16_t*>(packet+36)))); //show Des IP & Port Info
                //printfPacket(packet, 54);
                printfTcpData(packet);
            }
        }
        */
    }
    free(ethernet_hdr);
    free(ip_hdr);
    free(tcp_hdr);

    pcap_close(handle);
    return 0;
}
