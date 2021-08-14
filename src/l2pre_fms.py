#!/usr/bin/env python

"""
Something like
https://github.com/vs-uulm/nemesys/blob/c03cafdaed3175647d5bc690488742745acbd0eb/src/nemesys_fms.py
adopted to test l2pre with Fomat Match Score (FMS)
"""

# system import
import argparse
from IPython import embed
from time import time

# nemere import
from nemere.validation.dissectorMatcher import MessageComparator, DissectorMatcher
from nemere.utils.loader import SpecimenLoader
from nemere.utils import reportWriter

# netzob import
from netzob.Model.Vocabulary.Field import Field
from netzob.Model.Vocabulary.Types.Raw import Raw

# internal import
from utils import import_messages
from l2pre import analyze


debug = False
"""Some modules and methods contain debug output that can be activated by this flag."""


def prepareMessages(symbols, specimens):
    """Restores content of symbol.messages to the original, not deduplicated messages, including the
    payload and appends a payload field to symbol.fields. Afterwards, connect the message object of
    the comparator to the symbol, so that it is able to compare the format.
    """

    def applySpecimenMessage(sym):
        # match specimenloader logic by using their message object
        newmsgs = []
        for m in sym.messages:
            newmsg = None
            for specmsg in specimens.messagePool.keys():
                if m.data == specmsg.data and m.date == specmsg.date:
                    newmsg = specmsg
                    break
            if not newmsg:
                raise
            newmsgs.append(newmsg)
        sym.messages = newmsgs

    # restore original messages, as l2pre normally only outputs the unique ones
    for sym in symbols:
        if sym.orig_messages:
            sym.messages = list(sym.orig_messages)
        else:
            raise ValueError("orig_messages do not exist")

    # restore payload data by adding a field to symbol and appending payload data again
    for sym in symbols:

        # check if payloads exist and what the max size is (for payload field)
        payloads = []
        for m in sym.messages:
            if m.payload:
                payloads.append(m.payload_data)
        if payloads:
            max_payload_size = max([len(pl) for pl in payloads])
        else:
            applySpecimenMessage(sym)
            continue
        max_payload_size *= 8 # bits, not bytes

        # create and add payload field
        payload_field = Field(Raw(nbBytes=(0, max_payload_size)))
        sym.fields.append(payload_field)

        # append payload data to message.data
        for m in sym.messages:
            if m.payload:
                m.data += m.payload_data

        applySpecimenMessage(sym)


def main(args):

    print("Load messages...")
    # for FMS stuff
    # TODO import multiple files in SpecimenLoader and everywhere else, basically...
    specimens = SpecimenLoader(args.files[0], layer=args.layer,
                               relativeToIP=False)
    comparator = MessageComparator(specimens, pcap=args.files[0], 
                               failOnUndissectable=False, debug=debug)
    # for l2pre
    messages_list = import_messages(args.files, importLayer=args.layer)

    print("Infer protocol via l2pre tool...")
    inference_title = 'l2pre_inferred'
    inference_start_time = time()
    symbols = analyze(messages_list, args)
    inference_runtime = time() - inference_start_time

    # prepare messages to have the format, the comparator expects
    prepareMessages(symbols, specimens)

    # print inference results
    comparator.pprintInterleaved(symbols)

    # calc FMS per message
    print("\nCalculate FMS...\n")
    fms = DissectorMatcher.symbolListFMS(comparator, symbols)

    # write report
    reportWriter.writeReport(fms, inference_runtime, specimens, comparator, inference_title)

    if args.interactive:
        print("Start interactive session...\n")
        print('Loaded PCAP in: specimens, comparator, messages_list')
        print('Inferred messages in: symbols')
        print('FMS of messages in: message2quality')
        embed()

    return


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description='Reverse engineer a layer 2 protocol with l2pre and evaluate against tshark '
                    'dissectors: Write a report containing the Format Match Score (FMS) for each '
                    'message and other evaluation data.')

    parser.add_argument('files', help='pcap/pcapng files with network traffic to be analyzed', \
                        metavar='PCAPs', nargs='+')
    parser.add_argument('-l', '--layer', default=1, type=int, \
            help='Layer to import, defaults to 1 (use 2 if importing stuff in Radiotap header)')
    parser.add_argument('-nt', '--no-tunnel', action='store_true', default=False, \
            help='Do not look for Ethernet frames while searching for payloads. To use in case ' + \
            'of layer 2 replacements of Ethernet, but NOT in case of tunneled Ethernet+X traffic')
    parser.add_argument('-i', '--interactive', action='store_true', \
            help='start interactive session after automatic protocol reversing')

    args = parser.parse_args()

    main(args)
