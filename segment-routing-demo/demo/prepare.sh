#/usr/bin/sh

source config.cfg

ln -s ${CARD_DEVICE_FILE} /dev/alt_pf90
ip link set ${RX_NETDEV} promisc on
ip link set ${TX_NETDEV} promisc on

