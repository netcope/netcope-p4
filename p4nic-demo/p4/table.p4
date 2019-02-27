//
// \file table.p4
// \brief Definition of tables and actions for the P4 NIC example.
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

// Register array to count all packets [0], received packets [1], received bytes [2] and dropped packets [3]

#define COUNTERS_PKTS        0
#define COUNTERS_RCVD        1
#define COUNTERS_RCVD_BYTES  2
#define COUNTERS_DROPPED     3

register counters {
    width : 32;
    static : table_mac_filter;
    instance_count : 4;
}    

// Update counters and drop the packet
action _drop() {
    // Update packet counter
    register_read(packet_metadata.pkts, counters, COUNTERS_PKTS);
    add_to_field(packet_metadata.pkts, 1);
    register_write(counters, COUNTERS_PKTS, packet_metadata.pkts);

    // Update counter of dropped packet
    register_read(packet_metadata.dropped, counters, COUNTERS_DROPPED);
    add_to_field(packet_metadata.dropped, 1);
    register_write(counters, COUNTERS_DROPPED, packet_metadata.dropped);

    // Drop packet after updating
    drop();
}

// Update counters and computes the index to the RSS indirection table
action compute_rss() {
    // Increase packets counter
    register_read(packet_metadata.pkts, counters, COUNTERS_PKTS);
    add_to_field(packet_metadata.pkts, 1);
    register_write(counters, COUNTERS_PKTS, packet_metadata.pkts);

    // Increase counter of received packets
    register_read(packet_metadata.rcvd, counters, COUNTERS_RCVD);
    add_to_field(packet_metadata.rcvd, 1);
    register_write(counters, COUNTERS_RCVD, packet_metadata.rcvd);

    // Update byte counter of received packets
    register_read(packet_metadata.rcvd_bytes, counters, COUNTERS_RCVD_BYTES);
    add_to_field(packet_metadata.rcvd_bytes, intrinsic_metadata.packet_len);
    register_write(counters, COUNTERS_RCVD_BYTES, packet_metadata.rcvd_bytes);

    // Compute the index to the RSS indirection table
    modify_field_with_hash_based_offset(packet_metadata.rss_index, 0, ipv46_tcp_udp_csum, 65536);

    // Store the index to be passed together with the packet
    modify_field(intrinsic_metadata.hash, packet_metadata.rss_index);
}

// MAC address check (non-promiscuous mode)
table table_mac_filter {
    reads {
        ethernet.dstAddr : exact;
    }

    actions {
        compute_rss;
        _drop;
    }

    size: 1;
}

// Overwrites egress port based on the RSS indirection table
action update_egress_spec(spec) {
    modify_field(intrinsic_metadata.egress_port, spec);
}

// RSS indirection table
table table_rss {
    reads {
        packet_metadata.rss_index : exact;
    }

    actions {
        update_egress_spec;    
    }

    size: 16;
}
