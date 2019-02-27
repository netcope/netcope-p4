P4 NIC Example by Netcope Technologies
======================================

More information can be found in the [whitepaper][NetcopeWhitepaper].

The example implements a NIC (network interface card) with simple features:

1. **MAC address filtering**  
     A MAC address defined in the only item of the `table_mac_filter` table
     is used to filter incoming traffic.

2. **Gathering basic statistics**  
     There are four counters for:  
       I. Incoming packets  
       II. Received packets  
       III. Received bytes  
       IV. Dropped packets

3. **RSS load balancing**  
     Indirection table is stored in the table `table_rss`.

The NIC supports both IPv4 and IPv6. It also supports IEEE 802.1Q
protocol (aka VLAN tagging).

The list of files:

  * _commands.txt:_ sample run-time configuration for bmv2
  * _commands.np4:_ sample run-time configuration for Netcope P4
  * _rss-wireshark-imap.pcap:_ sample PCAP file taken from [Wireshark Wiki][WiresharkCaptures]
  * _p4/:_ folder with P4 source code files

[WiresharkCaptures]: https://wiki.wireshark.org/SampleCaptures
[NetcopeWhitepaper]: https://www.netcope.com/en/company/press-center
