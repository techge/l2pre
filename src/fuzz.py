#!/usr/bin/env python

# system import
import argparse

# others
from boofuzz.connections.raw_l2_socket_connection import RawL2SocketConnection 
from boofuzz import Session, Target
from boofuzz.monitors.base_monitor import BaseMonitor

# internal import
from boofuzz_template import *


# imports for IEEE80211Monitor
from scapy.all import sniff
from time import time

class IEEE80211Monitor(BaseMonitor):
    def __init__(self, interface, stop_filter, timeout=0.5):
        self.interface = interface
        self.stop_filter = stop_filter
        self.timeout = timeout
        return

    def post_send(self, target=None, fuzz_data_logger=None, session=None):

        oldtime = time()

        # sniff for one second, stop if stop_filter applied to a sniffed packet
        sniff(iface=self.interface, stop_filter=self.stop_filter, timeout=1)

        if time() - oldtime > self.timeout: # it took too long, it seems the target is/was down
            return False
        else:
            return True


def main(args):

    # define monitors
    #monitors = None
    stop_filter = lambda x: x.type == 3
    monitors = [IEEE80211Monitor(args.interface, stop_filter)]

    # create session
    session = Session(
        target=Target(
            connection=RawL2SocketConnection(args.interface,
                                             send_timeout=5.0,
                                             recv_timeout=5.0,
                                             ethernet_proto=0,
                                             mtu=2500,
                                             has_framecheck=True),
            monitors=monitors))

    # include all frames in boofuzz_template
    for frame in frames:
        session.connect(frame)

    # start fuzzing
    session.fuzz()

    return


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Fuzzing with boofuzz")

    parser.add_argument('-i', '--interface', required=True, \
            help='Interface to transmit and receive packets')

    # TODO check if args.interface is a valid socket

    args = parser.parse_args()

    main(args)
