//
// main.p4: Top-level P4 source file for router program
//
// Copyright (C) 2019 Netcope Technologies, a.s.
//
// Author(s):
//   Jan Remes <remes@netcope.com>
//
// SPDX-License-Identifier: GPL-3.0

#include "parser_newnat.p4"

#define NETCOPE_IMPLEMENTATION


#ifdef NETCOPE_IMPLEMENTATION

#define INGRESS_PORT    intrinsic_metadata.ingress_port
#define EGRESS_PORT     intrinsic_metadata.egress_port
#define PACKET_LENGTH   intrinsic_metadata.packet_len
#define LOG_SW_IFACES   2

#else

#define INGRESS_PORT    standard_metadata.ingress_port
#define EGRESS_PORT     standard_metadata.egress_spec
#define PACKET_LENGTH   standard_metadata.packet_length
#define LOG_SW_IFACES   1

#endif

/* ----[ IDENTIFICATION ]---------------------------------------------------- */
@pragma core_identification nat-demo-0.7

/* ----[ METADATA ]---------------------------------------------------------- */
header_type nat_metadata_t {
    fields {
        do_nat      : 1;
        padding_8b  : 8;
        tcp_length  : 16;
    }
}

metadata nat_metadata_t nat_metadata;

/* ----[ CHECKSUMS ]--------------------------------------------------------- */

/* ~~~~~~ IPv4 ~~~~~~ */

// Define field list of IPv4 header
field_list ipv4_fields {
    ipv4.version;
    ipv4.ihl;
    ipv4.dscp;
    ipv4.ecn;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    // hdrChecksum is taken as 0s - therefore it can be ignored
    //ipv4.hdrChecksum;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

// Define field list calculation of IPv4 checksum
field_list_calculation ipv4_csum {
    input {
        ipv4_fields;
    }
    algorithm    : csum16;
    output_width : 16;
}

/* ~~~~~~ UDP ~~~~~~ */

field_list udp_csum_fields {
    // IP pseudo-header
    ipv4.srcAddr;
    ipv4.dstAddr;
    nat_metadata.padding_8b;
    ipv4.protocol;
    udp.udpLength;
    // UDP header
    udp.srcPort;
    udp.dstPort;
    udp.udpLength;
    //udp.checksum; for the algorithm, checksum == 0

#ifdef NETCOPE_IMPLEMENTATION
    payload_checksum.data;
#endif
}

field_list_calculation udp_csum {
    input {
        udp_csum_fields;
    }
    algorithm    : csum16;
    output_width : 16;
}

/* ~~~~~~ TCP ~~~~~~ */
field_list tcp_csum_fields {
    // IP pseudo-header
    ipv4.srcAddr;
    ipv4.dstAddr;
    nat_metadata.padding_8b;
    ipv4.protocol;
    nat_metadata.tcp_length;
    // TCP header
    tcp.srcPort;
    tcp.dstPort;
    tcp.seqNumber;
    tcp.ackNumber;
    tcp.dataOffset;
    tcp.reserved;
    tcp.flags;
    tcp.windowSize;
    //tcp.checksum; for the algorithm, checksum == 0
    tcp.urgPointer;

#ifdef NETCOPE_IMPLEMENTATION
    payload_checksum.data;
#endif
}

field_list_calculation tcp_csum {
    input {
        tcp_csum_fields;
    }
    algorithm    : csum16;
    output_width : 16;
}


/* ----[ ACTIONS ]----------------------------------------------------------- */

action enable_nat() {
    set_nat_metadata(1);
}

action disable_nat() {
    set_nat_metadata(0);
}

action set_nat_metadata(do_nat) {
    modify_field(nat_metadata.do_nat, do_nat);

    modify_field(nat_metadata.padding_8b, 0);

    /* TCP length is the packet length minus length of Ethernet and IPv4 */
    modify_field(nat_metadata.tcp_length, PACKET_LENGTH);
    subtract_from_field(nat_metadata.tcp_length, 14);
    subtract_from_field(nat_metadata.tcp_length, 20);
}

action srcnat_tcp(ipaddr, port) {
    modify_field(ipv4.srcAddr, ipaddr);
    modify_field_with_hash_based_offset(ipv4.hdrChecksum,0,ipv4_csum,65536);
    modify_field(tcp.srcPort, port);
    modify_field_with_hash_based_offset(tcp.checksum,0,tcp_csum,65536);
}

action dstnat_tcp(ipaddr, port) {
    modify_field(ipv4.dstAddr, ipaddr);
    modify_field_with_hash_based_offset(ipv4.hdrChecksum,0,ipv4_csum,65536);
    modify_field(tcp.dstPort, port);
    modify_field_with_hash_based_offset(tcp.checksum,0,tcp_csum,65536);
}

action srcnat_udp(ipaddr, port) {
    modify_field(ipv4.srcAddr, ipaddr);
    modify_field_with_hash_based_offset(ipv4.hdrChecksum,0,ipv4_csum,65536);
    modify_field(udp.srcPort, port);
    modify_field_with_hash_based_offset(udp.checksum,0,udp_csum,65536);
}

action dstnat_udp(ipaddr, port) {
    modify_field(ipv4.dstAddr, ipaddr);
    modify_field_with_hash_based_offset(ipv4.hdrChecksum,0,ipv4_csum,65536);
    modify_field(udp.dstPort, port);
    modify_field_with_hash_based_offset(udp.checksum,0,udp_csum,65536);
}

action set_egress_port(eport) {
    modify_field(EGRESS_PORT, eport);
}

/* ----[ TABLES ]------------------------------------------------------------ */
table tab_extract_nat_metadata {
    reads {
        INGRESS_PORT : ternary;
        ipv4.srcAddr : ternary;
    }

    actions {
        enable_nat;
        disable_nat;
    }

    max_size : 7;
}

@pragma use_external_mem true
table tab_nat {
    reads {
        ipv4.srcAddr : exact;
        ipv4.dstAddr : exact;
        tcp          : valid;
        tcp.srcPort  : exact;
        tcp.dstPort  : exact;
        udp          : valid;
        udp.srcPort  : exact;
        udp.dstPort  : exact;
    }

    actions {
        srcnat_tcp;
        srcnat_udp;
        dstnat_tcp;
        dstnat_udp;
    }

    max_size : 33554432;
}

table tab_set_egress_port {
    reads {
        INGRESS_PORT : exact;
        nat_metadata.do_nat : exact;
    }

    actions {
        set_egress_port;
    }

    max_size : 7;
}

/* ----[ CONTROL ]----------------------------------------------------------- */
control ingress {
    apply(tab_extract_nat_metadata);

    if (nat_metadata.do_nat == 1) {
        apply(tab_nat);
    }

    apply(tab_set_egress_port);
}
