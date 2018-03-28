/*
 * np4_int.cpp: Source of simple INT processing example.
 * Copyright (C) 2018 Netcope Technologies, a.s.
 * Author(s): Tomas Zavodnik <zavodnik@netcope.com>
 * Description:
 * --------------------------------------------------------------------------------
 * ------------------- Netcope P4 INT processing example --------------------------
 * --------------------------------------------------------------------------------
 * - This example application implements simple processing of INT, including      -
 *   detection, extraction and capture of INT headers, and sending Telemetry      -
 *   reports.                                                                     -
 * --------------------------------------------------------------------------------
 * Usage: np4_int [-hvo] [-d card] -r queue -t ip [-p port]
 *   -d card  Card to use (default: 0)
 *   -r queue RX queue to use for metadata
 *   -t ip    Target IPv4 address for Telemetry reports
 *   -p port  Target UDP port for Telemetry reports (default: 32766)
 *   -o       Keep original packets, don't remove INT on output
 *   -h       Writes out help
 *   -v       Verbose mode
 * --------------------------------------------------------------------------------
 */

 /*
 * This file is part of Netcope distribution (https://github.com/netcope).
 * Copyright (c) 2018 Netcope Technologies, a.s.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <iostream>
#include <cstring>
#include <bitset>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

// Netcope P4 library
#include <libnp4.h>

#include "arguments.hpp"

/**
 * \brief Netcope P4 INT header
 */
typedef struct __attribute__((__packed__)) np4_int_header {
    uint32_t                source_ip[4];
    uint32_t                destination_ip[4];
    uint16_t                source_port;
    uint16_t                destination_port;
    uint8_t                 ip_ver;
    uint8_t                 l4_proto;
    uint16_t                reserved16_1;
    uint8_t                 int_length;
    uint8_t                 int_inscnt   : 5;
    uint8_t                 int_vld      : 1;
    uint8_t                 int_hop1_vld : 1;
    uint8_t                 int_hop0_vld : 1;
    uint16_t                int_insmap;
    uint32_t                reserved32_1;

    uint32_t                int_hop0_swid;
    uint16_t                int_hop0_ingressport;
    uint16_t                int_hop0_egressport;
    uint32_t                int_hop0_hoplatency;
    uint32_t                int_hop0_occupancy_queueid   : 8;
    uint32_t                int_hop0_occupancy_occupancy : 24;
    uint32_t                int_hop0_ingresstimestamp;
    uint32_t                int_hop0_egresstimestamp;
    uint32_t                int_hop0_congestion_queueid    : 8;
    uint32_t                int_hop0_congestion_congestion : 24;
    uint32_t                int_hop0_egressporttxutilization;

    uint32_t                int_hop1_swid;
    uint16_t                int_hop1_ingressport;
    uint16_t                int_hop1_egressport;
    uint32_t                int_hop1_hoplatency;
    uint32_t                int_hop1_occupancy_queueid   : 8;
    uint32_t                int_hop1_occupancy_occupancy : 24;
    uint32_t                int_hop1_ingresstimestamp;
    uint32_t                int_hop1_egresstimestamp;
    uint32_t                int_hop1_congestion_queueid    : 8;
    uint32_t                int_hop1_congestion_congestion : 24;
    uint32_t                int_hop1_egressporttxutilization;
} np4_int_header_t;

/**
 * \brief Telemetry Report header
 */
struct __attribute__((__packed__)) telemetry_report
{
    uint8_t    nproto: 4;
    uint8_t    ver   : 4;
    uint16_t   res16;
    uint8_t    hw_id : 6;
    uint8_t    res2  : 2;
    uint32_t   sequence_number;
    uint32_t   ingress_timestamp;
};

/**
 * \brief Ethernet header
 */
struct __attribute__((__packed__)) ethernet
{
    uint8_t    dmac[6];
    uint8_t    smac[6];
    uint16_t   ethtype;
};

/**
 * \brief INT Shim header
 */
struct __attribute__((__packed__)) int_shim
{
    uint8_t    type;
    uint8_t    res1;
    uint8_t    length;
    uint8_t    res2;
};

/**
 * \brief INT header
 */
struct __attribute__((__packed__)) int_hdr
{
    uint8_t    res4 : 4;
    uint8_t    ver  : 4;
    uint8_t    ins_cnt : 5;
    uint8_t    res3    : 3;
    uint8_t    max_hop_cnt;
    uint8_t    total_hop_cnt;
    uint16_t   instr_bitmap;
    uint16_t   reserved;
};

/**
 * \brief INT Tail header
 */
struct __attribute__((__packed__)) int_tail
{
    uint8_t    proto;
    uint16_t   dport;
    uint8_t    dscp;
};

bool run = true;

/**
 * \brief Function for calculating IP checksum
 * @param vdata  Pointer to IP header
 * @param length Length of IP header
 * Source: http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html
 */
uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint64_t acc=0xffff;

    // Handle any partial block at the start of the data.
    unsigned int offset=((uintptr_t)data)&3;
    if (offset) {
        size_t count=4-offset;
        if (count>length) count=length;
        uint32_t word=0;
        memcpy(offset+(char*)&word,data,count);
        acc+=ntohl(word);
        data+=count;
        length-=count;
    }

    // Handle any complete 32-bit blocks.
    char* data_end=data+(length&~3);
    while (data!=data_end) {
        uint32_t word;
        memcpy(&word,data,4);
        acc+=ntohl(word);
        data+=4;
    }
    length&=3;

    // Handle any partial block at the end of the data.
    if (length) {
        uint32_t word=0;
        memcpy(&word,data,length);
        acc+=ntohl(word);
    }

    // Handle deferred carries.
    acc=(acc&0xffffffff)+(acc>>32);
    while (acc>>16) {
        acc=(acc&0xffff)+(acc>>16);
    }

    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset&1) {
        acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

/**
 * \brief Packet processing function.
 * @param np4  Netcope P4 instance
 * @param args Parsed command line arguments
 */
void np4_processing(np4_t* np4, arguments const &args) {
    np4_rx_stream_t *rx_stream = NULL; // Netcope P4 RX stream
    unsigned char *data;               // Pointer to Netcope P4 input
    unsigned data_len;                 // Length of Netcope P4 input
    np4_header_t np4_hdr;              // Netcope P4 frame header
    np4_int_header_t *np4_int_hdr;     // Netcope P4 INT header
    np4_error_t err;                   // Netcope P4 error type
    unsigned frame_len;

    // Telemetry report packet types
    int sock;
    struct sockaddr_in sockaddr;
    char buffer[512] = { 0 };
    uint32_t seqnum = 0;

    try {
        // Prepare socket for Telemetry reports
        if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
            throw std::string("Socket error");
        }
        memset((char *) &sockaddr, 0, sizeof(sockaddr));
        sockaddr.sin_family = AF_INET;
        if (inet_aton(args.ip, &sockaddr.sin_addr) == 0)
        {
            throw std::string("IP address error");
        }

        // Prepare common IP header for Telemetry reports
        struct iphdr *ip = (struct iphdr *) &(buffer[0]);
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = 0;
        ip->id = 0;
        ip->frag_off = htons(0x4000);
        ip->ttl = 255;
        ip->protocol = 17;
        ip->check = 0;
        ip->saddr = 0;
        ip->daddr = sockaddr.sin_addr.s_addr;

        // Prepare common UDP header for Telemetry reports
        struct udphdr *udp = (struct udphdr *) &(buffer[20]);
        udp->source = 0;
        udp->dest = htons(args.port);
        udp->len = 0;
        udp->check = 0;

        // Open Netcope P4 RX stream
        err = np4_rx_stream_open(np4, args.rx_queue, &rx_stream);
        // Main processing loop
        while(run) {
            // Rry to read next Netcope P4 input
            data = np4_rx_stream_read_next(rx_stream, &data_len);
            // New Netcope P4 input
            if(data) {
                // Check length of Netcope INT header
                if (data_len == 128) {
                    // Parse Netcope P4 input into Netcope P4 header and Netcope INT header
                    err = np4_parse_frame(data, &np4_hdr, (unsigned char **) &np4_int_hdr, &frame_len);
                    if (err) {
                        throw np4_print_error(err);
                    }

                    // Debug output
                    if (args.verbose) {
                        std::cout << "Received INT header" << std::endl;
                        std::cout << "\tFlow ID:" << std::endl;
                        std::cout << "\t\tTimestamp           : " << np4_hdr.timestamp_s << "." << np4_hdr.timestamp_ns << std::endl;
                        std::cout << "\t\tInterface           : " << (unsigned) np4_hdr.iface << std::endl;
                        std::cout << "\t\tIP version          : " << (unsigned) np4_int_hdr->ip_ver << std::endl;
                        std::cout << "\t\tSource IPv4         : "
                                    << ((np4_int_hdr->source_ip[0] >> 24) & 0xFF) << "."
                                    << ((np4_int_hdr->source_ip[0] >> 16) & 0xFF) << "."
                                    << ((np4_int_hdr->source_ip[0] >> 8) & 0xFF) << "."
                                    << ((np4_int_hdr->source_ip[0] & 0xFF)) << std::endl;
                        std::cout << "\t\tDestination IPv4    : "
                                    << ((np4_int_hdr->destination_ip[0] >> 24) & 0xFF) << "."
                                    << ((np4_int_hdr->destination_ip[0] >> 16) & 0xFF) << "."
                                    << ((np4_int_hdr->destination_ip[0] >> 8) & 0xFF) << "."
                                    << ((np4_int_hdr->destination_ip[0] & 0xFF)) << std::endl;
                        std::cout << "\t\tL4 protocol         : " << (unsigned) np4_int_hdr->l4_proto << std::endl;
                        std::cout << "\t\tSource L4 port      : " << np4_int_hdr->source_port << std::endl;
                        std::cout << "\t\tDestination L4 port : " << np4_int_hdr->destination_port << std::endl;
                        std::cout << std::endl;
                        // If INT was detected
                        if (np4_int_hdr->int_vld) {
                            std::cout << "\tINT common:"  << std::endl;
                            std::cout << "\t\tLength              : " << (unsigned) np4_int_hdr->int_length << std::endl;
                            std::cout << "\t\tInstruction count   : " << (unsigned) np4_int_hdr->int_inscnt << std::endl;
                            std::cout << "\t\tInstruction map     : " << std::bitset<16>(np4_int_hdr->int_insmap) << std::endl;
                            std::cout << std::endl;
                            // If INT Hop 0 was detected
                            if (np4_int_hdr->int_hop0_vld) {
                                std::cout << "\tINT hop 0:" << std::endl;
                                if (np4_int_hdr->int_insmap & 0x8000) std::cout << "\t\tSwitch ID           : " << np4_int_hdr->int_hop0_swid << std::endl;
                                if (np4_int_hdr->int_insmap & 0x4000) std::cout << "\t\tIngress port        : " << np4_int_hdr->int_hop0_ingressport << std::endl;
                                if (np4_int_hdr->int_insmap & 0x4000) std::cout << "\t\tEgress port         : " << np4_int_hdr->int_hop0_egressport << std::endl;
                                if (np4_int_hdr->int_insmap & 0x2000) std::cout << "\t\tHop latency         : " << np4_int_hdr->int_hop0_hoplatency << std::endl;
                                if (np4_int_hdr->int_insmap & 0x1000) std::cout << "\t\tQueue occupancy     : " << np4_int_hdr->int_hop0_occupancy_queueid << " : " << np4_int_hdr->int_hop0_occupancy_occupancy << std::endl;
                                if (np4_int_hdr->int_insmap & 0x0800) std::cout << "\t\tIngress timestamp   : " << np4_int_hdr->int_hop0_ingresstimestamp << std::endl;
                                if (np4_int_hdr->int_insmap & 0x0400) std::cout << "\t\tEgress timestamp    : " << np4_int_hdr->int_hop0_egresstimestamp << std::endl;
                                if (np4_int_hdr->int_insmap & 0x0200) std::cout << "\t\tQueue congestion    : " << np4_int_hdr->int_hop0_congestion_queueid << " : " << np4_int_hdr->int_hop0_congestion_congestion << std::endl;
                                if (np4_int_hdr->int_insmap & 0x0100) std::cout << "\t\tEgress port TX util.: " << np4_int_hdr->int_hop0_egressporttxutilization << std::endl;
                            }
                            // If INT Hop 1 was detected
                            if (np4_int_hdr->int_hop1_vld) {
                                std::cout << "\tINT hop 1:" << std::endl;
                                if (np4_int_hdr->int_insmap & 0x8000) std::cout << "\t\tSwitch ID           : " << np4_int_hdr->int_hop1_swid << std::endl;
                                if (np4_int_hdr->int_insmap & 0x4000) std::cout << "\t\tIngress port        : " << np4_int_hdr->int_hop1_ingressport << std::endl;
                                if (np4_int_hdr->int_insmap & 0x4000) std::cout << "\t\tEgress port         : " << np4_int_hdr->int_hop1_egressport << std::endl;
                                if (np4_int_hdr->int_insmap & 0x2000) std::cout << "\t\tHop latency         : " << np4_int_hdr->int_hop1_hoplatency << std::endl;
                                if (np4_int_hdr->int_insmap & 0x1000) std::cout << "\t\tQueue occupancy     : " << np4_int_hdr->int_hop1_occupancy_queueid << " : " << np4_int_hdr->int_hop1_occupancy_occupancy << std::endl;
                                if (np4_int_hdr->int_insmap & 0x0800) std::cout << "\t\tIngress timestamp   : " << np4_int_hdr->int_hop1_ingresstimestamp << std::endl;
                                if (np4_int_hdr->int_insmap & 0x0400) std::cout << "\t\tEgress timestamp    : " << np4_int_hdr->int_hop1_egresstimestamp << std::endl;
                                if (np4_int_hdr->int_insmap & 0x0200) std::cout << "\t\tQueue congestion    : " << np4_int_hdr->int_hop1_congestion_queueid << " : " << np4_int_hdr->int_hop1_congestion_congestion << std::endl;
                                if (np4_int_hdr->int_insmap & 0x0100) std::cout << "\t\tEgress port TX util.: " << np4_int_hdr->int_hop1_egressporttxutilization << std::endl;
                            }
                        } else {
                            std::cout << "\tINT not detected." << std::endl;
                        }
                    }

                    // Prepare and send Telemetry report if INT was detected
                    if (np4_int_hdr->int_vld) {
                        // Prepare Telemetry report header
                        struct telemetry_report *tel = (struct telemetry_report *) &(buffer[28]);
                        tel->ver = 0;
                        tel->nproto = 0;
                        tel->res16 = htons(0x2000);
                        tel->res2 = 0;
                        tel->hw_id = 1;
                        tel->sequence_number = htonl(++seqnum);
                        tel->ingress_timestamp = htonl(np4_hdr.timestamp_s);

                        // Prepare Ethernet header
                        struct ethernet *eth_in = (struct ethernet *) &(buffer[40]);
                        eth_in->dmac[0] = 0x01; eth_in->dmac[1] = 0x02; eth_in->dmac[2] = 0x03; eth_in->dmac[3] = 0x04; eth_in->dmac[4] = 0x05; eth_in->dmac[5] = 0x06; // Static
                        eth_in->smac[0] = 0x11; eth_in->smac[1] = 0x12; eth_in->smac[2] = 0x13; eth_in->smac[3] = 0x14; eth_in->smac[4] = 0x15; eth_in->smac[5] = 0x16; // Static
                        eth_in->ethtype = htons(0x0800); // Static

                        // Prepare Ethernet header
                        struct iphdr *ip_in = (struct iphdr *) &(buffer[54]);
                        ip_in->ihl = 5; // Static
                        ip_in->version = 4; // Static
                        ip_in->tos = 0x80; // Static
                        ip_in->tot_len = 0; // Actual length is used
                        ip_in->id = 0; // Static
                        ip_in->frag_off = htons(0x4000); // Static
                        ip_in->ttl = 255; // Static
                        ip_in->protocol = np4_int_hdr->l4_proto;
                        ip_in->check = 0; // Actual checksum is used
                        ip_in->saddr = htonl(np4_int_hdr->source_ip[0]);
                        ip_in->daddr = htonl(np4_int_hdr->destination_ip[0]);

                        // Prepare UDP header
                        struct udphdr *udp_in = (struct udphdr *) &(buffer[74]);
                        udp_in->source = htons(np4_int_hdr->source_port);
                        udp_in->dest = htons(np4_int_hdr->destination_port);
                        udp_in->len = 0; // Actual length is used
                        udp_in->check = 0; // Static

                        // Prepare INT Shim header
                        struct int_shim *int_sh = (struct int_shim *) &(buffer[82]);
                        int_sh->type = 1; // Static
                        int_sh->res1 = 0;
                        int_sh->length = np4_int_hdr->int_length;
                        int_sh->res2 = 0;

                        // Prepare INT header
                        struct int_hdr *int_h = (struct int_hdr *) &(buffer[82+4]);
                        int_h->ver = 0; // Static
                        int_h->res4 = 0;
                        int_h->ins_cnt = np4_int_hdr->int_inscnt;
                        int_h->res3 = 0;
                        int_h->max_hop_cnt = 0; // Static
                        int_h->total_hop_cnt = 0; // Static
                        if (np4_int_hdr->int_hop0_vld) int_h->total_hop_cnt++;
                        if (np4_int_hdr->int_hop1_vld) int_h->total_hop_cnt++;
                        int_h->instr_bitmap = htons(np4_int_hdr->int_insmap);
                        int_h->reserved = 0;

                        unsigned index = 82+4+8;
                        if (np4_int_hdr->int_hop1_vld) {
                            if (np4_int_hdr->int_insmap & 0x8000) { *((uint32_t *) &(buffer[index])) = htonl(np4_int_hdr->int_hop1_swid); index += 4; }
                            if (np4_int_hdr->int_insmap & 0x4000) { *((uint16_t *) &(buffer[index])) = htons(np4_int_hdr->int_hop1_ingressport); index += 2; }
                            if (np4_int_hdr->int_insmap & 0x4000) { *((uint16_t *) &(buffer[index])) = htons(np4_int_hdr->int_hop1_egressport); index += 2; }
                            if (np4_int_hdr->int_insmap & 0x2000) { *((uint32_t *) &(buffer[index])) = htonl(np4_int_hdr->int_hop1_hoplatency); index += 4; }
                            if (np4_int_hdr->int_insmap & 0x1000) { *((uint8_t  *) &(buffer[index])) = np4_int_hdr->int_hop1_occupancy_queueid; index += 1; }
                            if (np4_int_hdr->int_insmap & 0x1000) { *((uint32_t *) &(buffer[index])) = htonl(np4_int_hdr->int_hop1_occupancy_occupancy)>>8; index += 3; }
                            if (np4_int_hdr->int_insmap & 0x0800) { *((uint32_t *) &(buffer[index])) = htonl(np4_int_hdr->int_hop1_ingresstimestamp); index += 4; }
                            if (np4_int_hdr->int_insmap & 0x0400) { *((uint32_t *) &(buffer[index])) = htonl(np4_int_hdr->int_hop1_egresstimestamp); index += 4; }
                            if (np4_int_hdr->int_insmap & 0x0200) { *((uint8_t  *) &(buffer[index])) = np4_int_hdr->int_hop1_congestion_queueid; index += 1; }
                            if (np4_int_hdr->int_insmap & 0x0200) { *((uint32_t *) &(buffer[index])) = htonl(np4_int_hdr->int_hop1_congestion_congestion)>>8; index += 3; }
                            if (np4_int_hdr->int_insmap & 0x0100) { *((uint32_t *) &(buffer[index])) = htonl(np4_int_hdr->int_hop1_egressporttxutilization); index += 4; }
                        }
                        if (np4_int_hdr->int_hop0_vld) {
                            if (np4_int_hdr->int_insmap & 0x8000) { *((uint32_t *) &(buffer[index])) = htonl(np4_int_hdr->int_hop0_swid); index += 4; }
                            if (np4_int_hdr->int_insmap & 0x4000) { *((uint16_t *) &(buffer[index])) = htons(np4_int_hdr->int_hop0_ingressport); index += 2; }
                            if (np4_int_hdr->int_insmap & 0x4000) { *((uint16_t *) &(buffer[index])) = htons(np4_int_hdr->int_hop0_egressport); index += 2; }
                            if (np4_int_hdr->int_insmap & 0x2000) { *((uint32_t *) &(buffer[index])) = htonl(np4_int_hdr->int_hop0_hoplatency); index += 4; }
                            if (np4_int_hdr->int_insmap & 0x1000) { *((uint8_t  *) &(buffer[index])) = np4_int_hdr->int_hop0_occupancy_queueid; index += 1; }
                            if (np4_int_hdr->int_insmap & 0x1000) { *((uint32_t *) &(buffer[index])) = htonl(np4_int_hdr->int_hop0_occupancy_occupancy)>>8; index += 3; }
                            if (np4_int_hdr->int_insmap & 0x0800) { *((uint32_t *) &(buffer[index])) = htonl(np4_int_hdr->int_hop0_ingresstimestamp); index += 4; }
                            if (np4_int_hdr->int_insmap & 0x0400) { *((uint32_t *) &(buffer[index])) = htonl(np4_int_hdr->int_hop0_egresstimestamp); index += 4; }
                            if (np4_int_hdr->int_insmap & 0x0200) { *((uint8_t  *) &(buffer[index])) = np4_int_hdr->int_hop0_congestion_queueid; index += 1; }
                            if (np4_int_hdr->int_insmap & 0x0200) { *((uint32_t *) &(buffer[index])) = htonl(np4_int_hdr->int_hop0_congestion_congestion)>>8; index += 3; }
                            if (np4_int_hdr->int_insmap & 0x0100) { *((uint32_t *) &(buffer[index])) = htonl(np4_int_hdr->int_hop0_egressporttxutilization); index += 4; }
                        }

                        // Prepare INT Tail header
                        struct int_tail *int_tl = (struct int_tail *) &(buffer[82+(np4_int_hdr->int_length<<2)-4]);
                        int_tl->proto = ip_in->protocol;
                        int_tl->dport = udp_in->dest;
                        int_tl->dscp = 0; // Static

                        // Prepare payload
                        char *payload = (char *) &(buffer[82+(np4_int_hdr->int_length<<2)]);
                        strncpy(payload, "Hello World", 11);

                        // Update lengths and checksums
                        udp->len = htons(8+12+14+20+8+(np4_int_hdr->int_length<<2)+11);
                        ip_in->tot_len = htons(20+8+(np4_int_hdr->int_length<<2)+11);
                        ip_in->check = ip_checksum(ip_in, 20);
                        udp_in->len = htons(8+(np4_int_hdr->int_length<<2)+11);

                        // Send Telemetry report
                        if (sendto(sock, buffer, 20+8+12+14+20+8+(np4_int_hdr->int_length<<2)+11, 0 , (struct sockaddr *) &sockaddr, sizeof(sockaddr)) == -1)
                        {
                            throw std::string("Packet send error");
                        }
                    }
                } else {
                    std::cerr << "Unexpected frame size (" << data_len << ")" << std::endl;
                }
            }
        }
    } catch(std::exception &e) {
        run = false;
        std::cerr << std::string() + __progname + ": " + e.what() + "\n";
    } catch(np4_error_t &e) {
        run = false;
    } catch(std::string message) {
        std::cerr << message << std::endl;
        run = false;
    }

    // Close Telemetry reports socket
    close(sock);

    // Close data receiving SZE channel
    if(rx_stream)
        np4_rx_stream_close(np4, &rx_stream);
}

/**
 * \brief Netcope P4 preparation function.
 * @param args Parsed command line arguments
 * @param np4  Netcope P4 instance
 */
inline void np4_preparation(arguments &args, np4_t **np4) {
    // Initialize Netcope P4
    np4_error_t err = np4_init_card(np4, args.card_id);
    if(err)
        throw np4_print_error(err);

    // Clear all tables (to not interfere with the rules we are about to load)
    np4_core_reset(*np4);

    // Netcope P4 rule
    np4_rule_t *rule;

    // Setting Netcope P4 tables
    if (args.original) {
        //// tab_remove_int
        // 1. Create rule datatype (with set table and index within the table)
        rule = np4_rule_create("tab_remove_int",0);
        // 2. Set action of the rule
        err = np4_rule_set_action(rule,"permit");
        if(err) {
            np4_rule_free(rule);
            throw np4_print_error(err);
        }
        // 3. Add rule
        err = np4_core_add_rule(*np4,rule);
        if(err) {
            np4_rule_free(rule);
            throw np4_print_error(err);
        }
        // 4. Free rule
        np4_rule_free(rule);

        //// tab_update_enc_L4
        // 1. Create rule datatype (with set table and index within the table)
        rule = np4_rule_create("tab_update_enc_L4",0);
        // 2. Set action of the rule
        err = np4_rule_set_action(rule,"permit");
        if(err) {
            np4_rule_free(rule);
            throw np4_print_error(err);
        }
        // 3. Add rule
        err = np4_core_add_rule(*np4,rule);
        if(err) {
            np4_rule_free(rule);
            throw np4_print_error(err);
        }
        // 4. Free rule
        np4_rule_free(rule);

        //// tab_update_L4
        // 1. Create rule datatype (with set table and index within the table)
        rule = np4_rule_create("tab_update_L4",0);
        // 2. Set action of the rule
        err = np4_rule_set_action(rule,"permit");
        if(err) {
            np4_rule_free(rule);
            throw np4_print_error(err);
        }
        // 3. Add rule
        err = np4_core_add_rule(*np4,rule);
        if(err) {
            np4_rule_free(rule);
            throw np4_print_error(err);
        }
        // 4. Free rule
        np4_rule_free(rule);
    } else {
        //// tab_remove_int
        // 1. Create rule datatype (with set table and index within the table)
        rule = np4_rule_create("tab_remove_int",0);
        // 2. Set action of the rule
        err = np4_rule_set_action(rule,"act_remove_int");
        if(err) {
            np4_rule_free(rule);
            throw np4_print_error(err);
        }
        // 3. Add rule
        err = np4_core_add_rule(*np4,rule);
        if(err) {
            np4_rule_free(rule);
            throw np4_print_error(err);
        }
        // 4. Free rule
        np4_rule_free(rule);

        //// tab_update_enc_L4
        // 1. Create rule datatype (with set table and index within the table)
        rule = np4_rule_create("tab_update_enc_L4",0);
        // 2. Set action of the rule
        err = np4_rule_set_action(rule,"update_enc_L4");
        if(err) {
            np4_rule_free(rule);
            throw np4_print_error(err);
        }
        // 3. Add rule
        err = np4_core_add_rule(*np4,rule);
        if(err) {
            np4_rule_free(rule);
            throw np4_print_error(err);
        }
        // 4. Free rule
        np4_rule_free(rule);

        //// tab_update_L4
        // 1. Create rule datatype (with set table and index within the table)
        rule = np4_rule_create("tab_update_L4",0);
        // 2. Set action of the rule
        err = np4_rule_set_action(rule,"update_L4");
        if(err) {
            np4_rule_free(rule);
            throw np4_print_error(err);
        }
        // 3. Add rule
        err = np4_core_add_rule(*np4,rule);
        if(err) {
            np4_rule_free(rule);
            throw np4_print_error(err);
        }
        // 4. Free rule
        np4_rule_free(rule);
    }

    //// tab_send
    // 1. Create rule datatype (with set table and index within the table)
    rule = np4_rule_create("tab_send",0);
    // 2. Set action of the rule
    err = np4_rule_set_action(rule,"send_to_dma");
    if(err) {
        np4_rule_free(rule);
        throw np4_print_error(err);
    }
    // 3. Add rule
    err = np4_core_add_rule(*np4,rule);
    if(err) {
        np4_rule_free(rule);
        throw np4_print_error(err);
    }
    // 4. Free rule
    np4_rule_free(rule);

    // Enable Netcope P4
    err = np4_core_enable(*np4);
    if(err)
        throw np4_print_error(err);
}

/**
 * \brief Program main function.
 * @param argc Number of arguments.
 * @param argv Arguments themself.
 * @return Zero on success, error code otherwise.
 */
int main(int argc, char *argv[]) {
    int exit_code = EXIT_SUCCESS;
    // Netcope P4 datatype
    np4_t* np4 = NULL;

    try {
        // Parse program command line arguments
        arguments args(argc, argv);
        // If help is requested to display, don't continue further
        if(args.help)
            arguments::usage();
        else {
            // Prepare Netcope P4
            np4_preparation(args, &np4);

            // Run processing
            np4_processing(np4, args);
        }
    } catch(std::exception &e) {
        std::cerr << __progname << ": " << e.what() << std::endl;
        exit_code = EXIT_FAILURE;
    } catch(np4_error_t &e) {
        exit_code = EXIT_FAILURE;
    }

    if(np4!=NULL)
        np4_exit(&np4);
    return exit_code;
}
