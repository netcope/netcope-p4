//
// \file calculated_fields.p4
// \brief Definition of hash computation for the P4 NIC example.
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

// Define field list of IPv4/IPv6 & TCP/UDP header
// From P4 spec:
// If any of the fields in the field_list_calc have a parent header that is
// not valid, then those fields are left out of the field list for the purposes
// of calculating the hash value.
field_list ipv46_tcp_udp_fields {
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv6.nextHeader;
    ipv6.srcAddr;
    ipv6.dstAddr;
    tcp_udp.srcPort;
    tcp_udp.dstPort;
}

// Define field list calculation of IPv4/IPv6 & TCP or UDP checksum
field_list_calculation ipv46_tcp_udp_csum {
    input
    {
        ipv46_tcp_udp_fields;
    }
    algorithm : csum16;
    output_width : 4;
}
