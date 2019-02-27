//
// \file top.p4
// \brief Top level control flow for the P4 NIC example.
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


#include "headers.p4"
#include "parser.p4"
#include "calculated_fields.p4"
#include "table.p4"
//#include "/home/netcope/P4/include/intrinsic_metadata.p4"

// The example implements a NIC (network interface card) with simple features:
//
// 1. MAC address filtering
//      A MAC address defined in the only item of the table_mac_filter table
//      is used to filter incoming traffic.
//
// 2. Gathering basic statistics
//      There are four counters for:
//        I. Incoming packets
//        II. Received packets
//        III. Received bytes
//        IV. Dropped packets
//
// 3. RSS load balancing
//
//      Indirection table is stored in the table table_rss
//
// The NIC supports both IPv4 and IPv6. It also supports IEEE 802.1Q
// protocol (aka VLAN tagging).

@pragma core_identification P4-NIC-example-v1.0.0
control ingress {
   if(valid(ethernet)){
       apply(table_mac_filter) {
           hit {
               apply(table_rss);
           }
       }
    }
}
