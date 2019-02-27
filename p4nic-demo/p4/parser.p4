//
// \file parser.p4
// \brief Definition of parser for the P4 NIC example.
// \author Netcope Technologies, a.s.
// \date 2019
// -----------------------------------------------------------------------------
//
// Company: Netcope Technologies, a.s.
//
// Project: P4 NIC
// -----------------------------------------------------------------------------
//
// (c) Copyright 2019 Netcope Technologies, a.s.
//   All rights reserved.
//
//   Please review the terms of the license agreement before using this
//   file. If you are not an authorized user, please destroy this
//   source code file and notify Netcope Technologies a.s. immediately 
//   that you inadvertently received an unauthorized copy.
//
// -----------------------------------------------------------------------------

// Prepare metadata ============================================================
metadata packet_metadata_t        packet_metadata; 

// Initial starting point ======================================================
parser start {
    return parse_ethernet;
}

// Ethernet ====================================================================
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86dd
#define ETHERTYPE_VLAN 0x8100, 0x9100, 0x9200, 0x9300
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

header ethernet_t ethernet;
parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_VLAN : parse_vlan;
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_IPV6 : parse_ipv6;
        default : ingress;
    }
}

// VLAN ========================================================================
header vlan_tag_t vlan_tag;
parser parse_vlan {
    extract(vlan_tag);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_IPV6 : parse_ipv6;
        default : ingress;
    }
}

// IPv4 ========================================================================
header ipv4_t ipv4;
parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.protocol) {
        IPPROTO_TCP, IPPROTO_UDP : parse_tcp_udp;
        default : ingress;
    }
}

// IPv6 ========================================================================
header ipv6_t ipv6;
parser parse_ipv6 {
    extract(ipv6);
    return select(ipv6.nextHeader) {
        IPPROTO_TCP, IPPROTO_UDP : parse_tcp_udp;
        default : ingress;
    }
}

// TCP or UDP ==================================================================
header tcp_udp_t tcp_udp;
parser parse_tcp_udp {
    extract(tcp_udp);
    return ingress;
}
