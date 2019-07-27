#pragma once
#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
int packetInsert(u_char* packet, libnet_ethernet_hdr** ethernet_hdr, libnet_ipv4_hdr** ip_hdr, libnet_tcp_hdr** tcp_hdr);
void printfMacInfo(libnet_ethernet_hdr* ethernet_hdr);
void printf_Ip_Port_Info(libnet_ipv4_hdr* ip_hdr, libnet_tcp_hdr* tcp_hdr);
void printfTcpData(libnet_ipv4_hdr* ip_hdr, libnet_tcp_hdr* tcp_hdr, const u_char* packet);
void printfTenPacket(const u_char* packet, u_int32_t lenght);

/*void printfPacket(const u_char* packet, int lenght);

void printfTcpData(const u_char* packet);
u_int16_t my_ntohs(u_int16_t);
u_int32_t my_ntohd(u_int32_t);
*/
