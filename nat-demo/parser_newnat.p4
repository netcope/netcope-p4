//
// parser_newnat.p4: Parser of protocol stack for Netcope P4 NAT
//
// Copyright (C) 2019 Netcope Technologies, a.s.
//
// Author(s):
//   Jan Remes <remes@netcope.com>
//
// SPDX-License-Identifier: GPL-3.0

#ifndef PARSER_FULL_P4
#define PARSER_FULL_P4

// ----[ INCLUDES ]-------------------------------------------------------------
#include "headers.p4"
#include "constants.p4"

// ----[ HEADERS (DATA) ]-------------------------------------------------------
header ethernet_t   ethernet;
header ipv4_t       ipv4;
header tcp_t        tcp;
header udp_t        udp;

// ----[ PARSE GRAPH ]----------------------------------------------------------

// Initial starting point ("start" is P4 keyword)
parser start {
	return parse_ethernet;
}

// Ethernet parse node
parser parse_ethernet {
	extract(ethernet);
	return select(ethernet.etherType) {
		ETHERTYPE_IPV4 : parse_ipv4;
		default        : ingress;
	}
}

// IPv4 parse node
parser parse_ipv4 {
	extract(ipv4);
	return select(ipv4.protocol) {
		IPPROTO_TCP  : parse_tcp;
		IPPROTO_UDP  : parse_udp;
		default      : ingress;
	}
}

// TCP parse node
parser parse_tcp {
	extract(tcp);
	return ingress;
}

// UDP parse node
parser parse_udp {
	extract(udp);
	return ingress;
}

#endif /* PARSER_FULL_P4 */
