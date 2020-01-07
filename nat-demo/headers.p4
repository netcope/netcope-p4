//
// headers.p4: Header definitions of Netcope P4 programs library
//
// Copyright (C) 2019 Netcope Technologies, a.s.
//
// Author(s):
//   Jan Remes <remes@netcope.com>
//
// SPDX-License-Identifier: GPL-3.0

#ifndef HEADERS_P4
#define HEADERS_P4

// ----[ Layer 2 protocol headers ]---------------------------------------------

// Ethernet (IEEE 802.3) frame header
header_type ethernet_t {
	fields {
		dstAddr   : 48;
		srcAddr   : 48;
		etherType : 16;
	}
}

// VLAN (802.1Q) header
//
// Because of the way packet parsing works, the TPID field of the header is
// already represented as 'etherType' in the Ethernet frame header. The
// 'etherType' in this header will be the original Ethernet frame etherType
header_type vlan_t {
	fields {
		pcp       : 3;
		cfi       : 1;
		vid       : 12;
		etherType : 16;
	}
}

// ----[ Layer 3 protocol headers ]---------------------------------------------

// IPv4 (RFC 791) header
//
// This definition does not work with IPv4 options (variable header length).
// This is due to limitations of the Netcope P4 implementation.
header_type ipv4_t {
	fields {
		version        : 4;
		ihl            : 4;
		dscp           : 6;
		ecn            : 2;
		totalLen       : 16;
		identification : 16;
		flags          : 3;
		fragOffset     : 13;
		ttl            : 8;
		protocol       : 8;
		hdrChecksum    : 16;
		srcAddr        : 32;
		dstAddr        : 32;
	}
}

// IPv6 header
header_type ipv6_t {
	fields {
		version       : 4;
		trafficClass  : 8;
		flowLabel     : 20;
		payloadLength : 16;
		nextHeader    : 8;
		hopLimit      : 8;
		srcAddr       : 128;
		dstAddr       : 128;
	}
}

// ----[ Layer 4 protocol headers ]---------------------------------------------

// ICMP (RFC 792) header
header_type icmp_t {
	fields {
		icmpType : 8;
		icmpCode : 8;
		checksum : 16;
		// further fields differ per type/code
	}
}

// TCP (RFC 793) header
header_type tcp_t {
	fields {
		srcPort    : 16;
		dstPort    : 16;
		seqNumber  : 32;
		ackNumber  : 32;
		dataOffset : 4;
		reserved   : 3;
		flags      : 9;
		windowSize : 16;
		checksum   : 16;
		urgPointer : 16;
	}
}

// UDP (RFC 768) header
header_type udp_t {
	fields {
		srcPort   : 16;
		dstPort   : 16;
		udpLength : 16;
		checksum  : 16;
	}
}

// TCP or UDP beginning of the header
header_type tcp_udp_t {
	fields {
		srcPort   : 16;
		dstPort   : 16;
	}
}

#endif /* HEADERS_P4 */
