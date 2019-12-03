//
// \file headers.p4
// \brief Definition of headers for the P4 NIC example.
// \author Netcope Technologies, a.s.
// \date 2019
// -----------------------------------------------------------------------------
//
// Company: Netcope Technologies, a.s.
//
// Project: P4 NIC
// -----------------------------------------------------------------------------
//
// (c) Copyright 2018 Netcope Technologies, a.s.
//   All rights reserved.
//
//   Please review the terms of the license agreement before using this
//   file. If you are not an authorized user, please destroy this
//   source code file and notify Netcope Technologies a.s. immediately 
//   that you inadvertently received an unauthorized copy.
//
// -----------------------------------------------------------------------------

// Metadata ====================================================================
header_type packet_metadata_t {
    fields {
        rss_index : 4;
        pkts : 32;
        rcvd : 32;
        rcvd_bytes : 32;
        dropped : 32;
    }
}

// Full version of Ethernet ====================================================
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

// Full version of VLAN ========================================================
header_type vlan_tag_t {
    fields {
        pcp : 3;
        cfi : 1;
        vid : 12;
        etherType : 16; 
    }
}

// Full version of IPv4 ========================================================
header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

// Full version of IPv6 ========================================================
header_type ipv6_t {
    fields {
        version : 4;
        trafficClass : 8;
        flowLabel : 20;
        payloadLength : 16;
        nextHeader : 8;
        hopLimit : 8;
        srcAddr : 128;
        dstAddr : 128;
    }
}

// Partial header of TCP or UDP ================================================
header_type tcp_udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        // The other fields are not necessary for this application
    }
}
