//
// \file parser.p4
// \brief Definitions of parse graph for segment routing example.
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

// General constants ===========================================================
#define IPV6_EXT_DEPTH	1

// Protocol numbers ============================================================
#define PROTOCOL_IPV6 		0x86dd
#define PROTOCOL_V6EXT	    0x2B

// Instances of headers ========================================================
// Outer header stack
metadata seg_meta_t     lastSeg;
header ethernet_t		ethernet_0;
header ipv6_t 			ipv6;
header ipv6_ext_t 		ipv6_ext;

header ipv6_seg_t       ipv6_seg0;
header ipv6_seg_t       ipv6_seg1;
header ipv6_seg_t       ipv6_seg2;
header ipv6_seg_t       ipv6_seg3;
header ipv6_seg_t       ipv6_seg4;
header ipv6_seg_t       ipv6_seg5;
header ipv6_seg_t       ipv6_seg6;
header ipv6_seg_t       ipv6_seg7;
header ipv6_seg_t       ipv6_seg8;
header ipv6_seg_t       ipv6_seg9;
header ipv6_seg_t       ipv6_seg10;
header ipv6_seg_t       ipv6_seg11;
header ipv6_seg_t       ipv6_seg12;
header ipv6_seg_t       ipv6_seg13;
header ipv6_seg_t       ipv6_seg14;
header ipv6_seg_t       ipv6_seg15;

// Parse graph =================================================================
// Start
parser start {
    return parse_ethernet;
}

// ethernet
parser parse_ethernet {
    extract(ethernet_0);
    return select(latest.etherType) {
        PROTOCOL_IPV6 	: parse_ipv6;
        default			: ingress;
    }
}

parser parse_ipv6 {
    extract(ipv6);
    return select(latest.nextHead)  {
        PROTOCOL_V6EXT : parse_ext;
        default        : ingress;
    }
}

parser parse_ext {
    extract(ipv6_ext);
    set_metadata(lastSeg.nextSeg,latest.next_seg);
    return select(lastSeg.nextSeg) {
        0 : ingress;
        default : parse_seg0;
    }
}

parser parse_seg0 {
    extract(ipv6_seg0);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        1 : ingress;
        default : parse_seg1;
    }
}

parser parse_seg1 {
    extract(ipv6_seg1);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        2 : ingress;
        default : parse_seg2;
    }
}

parser parse_seg2 {
    extract(ipv6_seg2);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        3 : ingress;
        default : parse_seg3;
    }
}

parser parse_seg3 {
    extract(ipv6_seg3);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        4 : ingress;
        default : parse_seg4;
    }
}

parser parse_seg4 {
    extract(ipv6_seg4);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        5 : ingress;
        default : parse_seg5;
    }
}

parser parse_seg5 {
    extract(ipv6_seg5);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        6: ingress;
        default : parse_seg6;
    }
}

parser parse_seg6 {
    extract(ipv6_seg6);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        7 : ingress;
        default : parse_seg7;
    }
}

parser parse_seg7 {
    extract(ipv6_seg7);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        8 : ingress;
        default : parse_seg8;
    }
}

parser parse_seg8 {
    extract(ipv6_seg8);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        9 : ingress;
        default : parse_seg9;
    }
}

parser parse_seg9 {
    extract(ipv6_seg9);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        10 : ingress;
        default : parse_seg10;
    }
}
parser parse_seg10 {
    extract(ipv6_seg10);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        11 : ingress;
        default : parse_seg11;
    }
}
parser parse_seg11 {
    extract(ipv6_seg11);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        12 : ingress;
        default : parse_seg12;
    }
}

parser parse_seg12 {
    extract(ipv6_seg12);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        13 : ingress;
        default : parse_seg13;
    }
}

parser parse_seg13 {
    extract(ipv6_seg13);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        14 : ingress;
        default : parse_seg14;
    }
}

parser parse_seg14 {
    extract(ipv6_seg14);
    set_metadata(lastSeg.segVal,latest.val);
    return select(lastSeg.nextSeg) {
        15 : ingress;
        default : parse_seg15;
    }
}

parser parse_seg15 {
    extract(ipv6_seg15);
    set_metadata(lastSeg.segVal,latest.val);
    return ingress;
}
