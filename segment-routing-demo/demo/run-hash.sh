#/usr/bin/sh

source config.cfg

# reload
# clean
rm -rf out.pcap out-basic.pcap out-hash.pcap

vim run.sh

# basic design info
clear
echo "------------------------------------------------------------"
echo "-- BASIC DESIGN INFORMATION --------------------------------"
echo "------------------------------------------------------------"
np4tool-intel core --info
#np4tool-intel core --status
read -n 1 -s

# -- First run --

vim rules.txt

clear
echo "------------------------------------------------------------"
echo "-- HASH FWD RUN --------------------------------------------"
echo "------------------------------------------------------------"
echo "1. Loading rules"
set -x
np4tool-intel core --load rules-hash-fwd.txt -i0
np4tool-intel core --load rules-hash-fwd.txt -i1
{ set +x; } 2>/dev/null
read -n 1 -s

echo "2. Enabling atoms"
set -x
np4tool-intel core --enable
{ set +x; } 2>/dev/null
read -n 1 -s

echo "3. Reading input PCAP"
set -x
wireshark data.pcap
{ set +x; } 2>/dev/null

echo "4. Setting up packet capture"
set -x
tcpdump -i ${RX_NETDEV} -w out-hash.pcap &
PID=$!
{ set +x; } 2>/dev/null
read -n 1 -s
sleep 1

echo "5. Sending in the input PCAP"
set -x
tcpreplay -i ${TX_NETDEV} data.pcap
{ set +x; } 2>/dev/null
sleep 2

echo "6. Ending packet capture"
kill -SIGINT $PID
sleep 1

echo "7. Showing output PCAP"
set -x
wireshark out-hash.pcap
{ set +x; } 2>/dev/null
