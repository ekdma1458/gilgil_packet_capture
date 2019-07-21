#include "printfpacket.h"

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
void printfMacInfo(char c, const u_char* packet){
    printf("%c_Mac:", c);
    for (int i = 0; i < 6; i++) {
        printf("%02x:", packet[i]);
        if(i==4){
            printf("%02x\r\n", packet[i+1]);
            break;
        }
    }
}
void printf_Ip_Port_Info(char c, u_int32_t ip, u_int16_t port){
    printf("%c_IP : ", c);
    printf("%d.%d.%d.%d:%d \r\n", (ip & 0xff000000) >> 24 , (ip & 0x00ff0000) >> 16, (ip & 0x0000ff00) >> 8, (ip & 0x000000ff), port);
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

