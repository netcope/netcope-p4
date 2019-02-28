//
// \file headers.p4
// \brief Definitions of headers of segment routing example.
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

header_type ethernet_t {
    fields {
        dstAddr     : 48;
        srcAddr     : 48;
        etherType   : 16;
    }
}

header_type ipv6_t {
     fields {
         ver         : 4;
         trafClass   : 8;
         flowLab     : 20;
         payLen      : 16;
         nextHead    : 8;
         hopLim      : 8;
         srcAddr     : 128;
         dstAddr     : 128;
     }
 }


//IPv6, extension header and segments
header_type ipv6_ext_t {
    fields {
        nextHead    : 8;
        pad0        : 16;
        next_seg    : 8;
        pad1        : 32;       
    }
    
}

header_type ipv6_seg_t {
    fields {
        val : 128;
    }
}

// Metadata
header_type seg_meta_t {
    fields {
        segVal : 128;
        nextSeg : 8;
    }
}
