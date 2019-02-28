//
// \file top.p4
// \brief Definitions of control flow for segment routing example.
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

#include "headers.p4"
#include "parser.p4"
#include "tables.p4"

// Just set identification string of the P4 core
@pragma core_identification segment_routing_intel
control ingress {
    // If any segment was valid
    if(valid(ipv6_seg0)) {
        // Apply the segment routing rewrite
        apply(tab_rewrite);
    }
    // Always apply possible egress port set
    apply(table_set_egress_port);
}
