#pragma once
#include <pcap.h>
#include <stdio.h>
void printfPacket(const u_char* packet, int lenght);
void printfMacInfo(char test,const u_char* packet);
void printf_Ip_Port_Info(char c, u_int32_t ip, u_int16_t port);
void printfTcpData(const u_char* packet);
void printfTenPacket(const u_char* packet, u_int32_t lenght);
u_int16_t my_ntohs(u_int16_t);
u_int32_t my_ntohd(u_int32_t);
