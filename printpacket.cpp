#include "printfpacket.h"

int packetInsert(u_char* packet, libnet_ethernet_hdr** ethernet_hdr, libnet_ipv4_hdr** ip_hdr, libnet_tcp_hdr** tcp_hdr){
    *ethernet_hdr = reinterpret_cast<libnet_ethernet_hdr*>(packet);
    if (ntohs((*ethernet_hdr)->ether_type) == ETHERTYPE_IP){
        *ip_hdr = reinterpret_cast<libnet_ipv4_hdr*>(packet + LIBNET_ETH_H);
        if((*ip_hdr)->ip_p == IPPROTO_TCP){
            *tcp_hdr = reinterpret_cast<libnet_tcp_hdr*>(packet + LIBNET_ETH_H + LIBNET_IPV4_H);
            return 1;
        }
    }
    return 0;
}
void printfMacInfo(libnet_ethernet_hdr* ethernet_hdr){
    printf("S_Mac  ");
    for (int i = 0; i < 5; i++) {
        printf("%02x:", ethernet_hdr->ether_shost[i]);
        if(i==4){
            printf("%02x\r\n", ethernet_hdr->ether_shost[i+1]);
            break;
        }
    }
    printf("D_Mac  ");
    for (int i = 0; i < 5; i++) {
        printf("%02x:", ethernet_hdr->ether_dhost[i]);
        if(i==4){
            printf("%02x\r\n", ethernet_hdr->ether_dhost[i+1]);
            break;
        }
    }
}
void printf_Ip_Port_Info(libnet_ipv4_hdr* ip_hdr, libnet_tcp_hdr* tcp_hdr){
    u_int32_t src = ntohl(ip_hdr->ip_src.s_addr);
    u_int32_t dst = ntohl(ip_hdr->ip_dst.s_addr);

    printf("S : %d.%d.%d.%d:%d \r\n", (src & 0xff000000) >> 24  , (src & 0x00ff0000) >> 16 , (src & 0x0000ff00) >> 8 , (src & 0x000000ff) , ntohs(tcp_hdr->th_sport) );
    printf("S : %d.%d.%d.%d:%d \r\n", (dst & 0xff000000) >> 24  , (dst & 0x00ff0000) >> 16 , (dst & 0x0000ff00) >> 8 , (dst & 0x000000ff) , ntohs(tcp_hdr->th_dport) );
}

void printfTcpData(libnet_ipv4_hdr* ip_hdr, libnet_tcp_hdr* tcp_hdr, const u_char* packet){
    u_int16_t TotalLen = ntohs(ip_hdr->ip_len);
    u_int8_t IpHeaderLen = ip_hdr->ip_hl * 4 ;   //Header_Len need to 4 because is rule and it need to Bitwise Operators because header_len located forward 4bit
    u_int8_t TcpHeaderLen = (tcp_hdr->th_off & 0xf0 >> 4 ) * 4;//Header_Len need to 4 because is rule and it need to Bitwise Operators because header_len located backward 4bit
    u_int32_t TcpData = TotalLen - IpHeaderLen - TcpHeaderLen;
    printf("TcpData : %d\r\n", TcpData);
    if(TcpData != 0){
        printfTenPacket(packet + (LIBNET_ETH_H + LIBNET_IPV4_H), TcpData);
    }
}

void printfTenPacket(const u_char* packet, u_int32_t lenght){
    for (u_int32_t i = 0 ;i < lenght; i++) {
        if(i == 10){
            break;
        }
        printf("%c", packet[i]);
    }
    printf("\t|");
    for (u_int32_t i = 0 ;i < lenght; i++) {
        if(i == 10){
            break;
        }
        printf(" %02x ", packet[i]);
    }
    printf("|\r\n");
}
/*
void printfPacket(const u_char* packet, int lenght ){
    for (int i = 0 ;i < lenght; i++) {
        printf("%02x ",packet[i]);
        if( (i + 1) % 16 == 0){
            printf("\r\n");
        }
    }

    printf("\r\n");
}
void printfTenPacket(const u_char* packet, u_int32_t lenght){
    for (u_int32_t i = 0 ;i < lenght; i++) {
        if(i == 10){
            break;
        }
        printf("%c", packet[i]);
    }
    printf("\t|");
    for (u_int32_t i = 0 ;i < lenght; i++) {
        if(i == 10){
            break;
        }
        printf(" %02x ", packet[i]);
    }
    printf("|\r\n");
}
void printfMacInfo(libnet_ethernet_hdr* ethernet_hdr){
    printf("S_Mac:");
    for (int i = 0; i < 6; i++) {
        printf("%02x:", ethernet_hdr->ether_shost[i]);
        if(i==4){
            printf("%02x\r\n", ethernet_hdr->ether_shost[i+1]);
            break;
        }
    }
    printf("D_Mac:");
    for (int i = 0; i < 6; i++) {
        printf("%02x:", ethernet_hdr->ether_dhost[i]);
        if(i==4){
            printf("%02x\r\n", ethernet_hdr->ether_dhost[i+1]);
            break;
        }
    }

}

void printfTcpData(const u_char* packet){
    u_int16_t TotalLen =  my_ntohs(*reinterpret_cast<const u_int16_t*>(packet+16));
    u_int8_t IpHeaderLen = (reinterpret_cast<u_int8_t>(*(packet+14)) & 0x0f) * 4;   //Header_Len need to 4 because is rule and it need to Bitwise Operators because header_len located forward 4bit
    u_int8_t TcpHeaderLen = ((reinterpret_cast<u_int8_t>(*(packet+46)) & 0xf0) >> 4) * 4;//Header_Len need to 4 because is rule and it need to Bitwise Operators because header_len located backward 4bit
    u_int32_t TcpData = TotalLen - IpHeaderLen - TcpHeaderLen;
    printf("Total Length : %5d\r\n", TotalLen);
    //printf("IP_Header_Length : %5d\r\n", IpHeaderLen); // original IP_Header_Len = IP_Header_Len * 4
    //printf("Tcp_Header_Length : %5d\r\n", TcpHeaderLen); // original TCP_Header_Len = TCP_Header_Len * 4
    //printf("TcpData : %d\r\n", TcpData);
    if(TcpData != 0){
        printfTenPacket(packet+(IpHeaderLen + TcpHeaderLen + 14) , TcpData);
    }
}

u_int16_t my_ntohs(u_int16_t port){
    return (port & 0x00ff) << 8 | (port & 0xff00) >> 8;
}

u_int32_t my_ntohd(u_int32_t ip){
    return (ip & 0xff000000) >> 24 | (ip & 0x00ff0000) >> 8 | (ip & 0x0000ff00) << 8 | (ip & 0x000000ff) << 24;
}
*/
