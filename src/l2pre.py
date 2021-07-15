#!/usr/bin/env python

# system import
import argparse
from IPython import embed
import sys

# netzob import
from netzob.Model.Vocabulary.Functions.EncodingFunctions.TypeEncodingFunction import TypeEncodingFunction
from netzob.Model.Vocabulary.Types.HexaString import HexaString

# internal import
from exportFunctions import *
from FeatureExtraction import FeatureExtraction
from PayloadFinder import PayloadFinder
from utils import import_messages


def analyze(messages_list: list, args):

    print("\nTry to find and cut off payloads with known protocols...")
    messages_list_without_payload = []
    finder = PayloadFinder()
    for msgs in messages_list:
        messages_list_without_payload.append(finder.findPayload(msgs, omit_ether=args.no_tunnel))

    # FIXME properly handle known_IPs/MACs
    known_MACs = finder.known_MACs
    known_MACs.add('d4:f5:27:41:88:c8')
    known_MACs.add('d4:f5:27:56:45:a0')
    known_MACs.add('38:10:d5:84:4d:06')
    known_MACs.add('3c:97:0e:61:c6:d4')

    print("\nStart feature detection...")
    features = FeatureExtraction(messages_list_without_payload, known_MACs)
    cluster = features.execute()

    return cluster


def main(args):

    print("\nImport PCAP files...")
    # import packets (each item on list 'messages' contains the messages of one file)
    messages_list = import_messages(args.files, importLayer=args.layer)

    # do the magic for layer 2 protocol reversing
    cluster = analyze(messages_list, args)

    # print symbols (omitting messages if there are too many)
    for symbol in cluster:
        msgs_backup = None
        print("\n{}: {} unique messages".format(symbol.name, str(len(symbol.messages))))
        # omit messages to have a nicer print...
        if len(symbol.messages) > 30:
            msgs_backup = symbol.messages
            symbol.messages = symbol.messages[0:30] # cut off long messages
            print("(only showing 30 here)")
        symbol.addEncodingFunction(TypeEncodingFunction(HexaString))
        print(symbol)
        # restore messages
        if msgs_backup:
            symbol.messages = list(msgs_backup)

    # optionally start interactive session
    if args.interactive:
        embed()

    # optionally export human-readable presentation (protocol format) to file
    if args.export_pf:
        exportPF(cluster)

    # optionally export boofuzz template
    if args.export_bf:
        exportFuzz(cluster)

    # optionally export wireshark dissector
    if args.export_ws:
        exportWiresharkDissector(cluster)

    return


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Layer 2 Protocol Reverse Engineering")

    parser.add_argument('files', help='pcap/pcapng files with network traffic to be analyzed', \
                        metavar='PCAPs', nargs='+')
    parser.add_argument('-l', '--layer', default=1, type=int, \
            help='Layer to import, defaults to 1 (use 2 if importing stuff in Radiotap header)')
    parser.add_argument('-nt', '--no-tunnel', action='store_true', default=False, \
            help='Do not look for Ethernet frames while searching for payloads. To use in case ' + \
            'of layer 2 replacements of Ethernet, but NOT in case of tunneled Ethernet+X traffic')
    parser.add_argument('-i', '--interactive', action='store_true', \
            help='start interactive session after automatic protocol reversing')
    parser.add_argument('-b', '--export-bf', action='store_true', \
            help='export boofuzz template')
    parser.add_argument('-e', '--export-pf', action='store_true', \
            help='export protocol format')
    parser.add_argument('-w', '--export-ws', action='store_true', \
            help='export wireshark dissector')

    args = parser.parse_args()

    if args.layer == 2 and args.no_tunnel:
        print("\nWARNING: You have chosen to parse layer 2 protocols (useful to get rid of " + \
                "Radiotap header, not recommended otherwise), but still you do not expect " + \
                "tunneled traffic, this is unusual, but proceeding nevertheless...")

    main(args)
