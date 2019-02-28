//
// \file tables.p4
// \brief Definitions of actions and tables of segment routing example.
// \author Pavel Benacek
// \date 2018
// -----------------------------------------------------------------------------
//
// Company: Netcope Technologies, a.s.
//
// Project: Segment routing
// -----------------------------------------------------------------------------
//
// (c) Copyright 2018 Netcope Technologies a.s.
//   All rights reserved.
//
//   Please review the terms of the license agreement before using this
//   file. If you are not an authorized user, please destroy this
//   source code file and notify Netcope Technologies a.s. immediately 
//   that you inadvertently received an unauthorized copy.
//
// -----------------------------------------------------------------------------

// Actions =====================================================================
// Rewrites destination IPv6 address with correct segment and decreases next_segment
action rewrite() {
    // Rewrite the destination IPv6 address with the last IPv6 segment
    modify_field(ipv6.dstAddr,lastSeg.segVal); 
    add_to_field(ipv6_ext.next_seg, -1);
}

// Sets egress port to specific value
action set_egress_port(eport) {
    modify_field(ethernet_0.dstAddr,eport);
}

#define BASE_DMA 0
#define NUM_OF_DMAS 65536
// Sets egress port to specific value
action forward_based_on_hash() {
    modify_field_with_hash_based_offset(ethernet_0.dstAddr, BASE_DMA, ipv6_hash, NUM_OF_DMAS);
}

// Allow the packet to go through unchanged
action permit() {
    no_op();
}

action drop_p() {
    drop();
}

// Tables ======================================================================

// Always run rewrite
table tab_rewrite {
    actions {
        rewrite;
    }
}

// Set egress port based on destination IPv6 address
table table_set_egress_port {
    reads {
        ipv6.dstAddr : ternary;
    }

    actions {
        drop_p;
        permit;
        set_egress_port;
        forward_based_on_hash;
    }

    max_size: 15;
}

// Definitions for hash ========================================================
// Define field list of IPv4 header
field_list ipv6_field_list {
    ipv6.dstAddr;
}

// Define field list calculation of IPv6
field_list_calculation ipv6_hash {
    input
    {
        ipv6_field_list;
    }
    algorithm : crc16;
    output_width : 16;
}
