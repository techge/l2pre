# in best case integrated into netzob later on
# netzob/src/netzob/Inference/Vocabulary/PayloadFinder.py or alike

# netzob import
from netzob.Common.Utils.Decorators import typeCheck
from netzob.Inference.Vocabulary.Format import Format
from netzob.Model.Vocabulary.Messages.RawMessage import RawMessage
from netzob.Model.Vocabulary.Messages.L2NetworkMessage import L2NetworkMessage

# internal import
from WithPayloadMessage import WithPayloadMessage

# external import
from scapy.all import Ether, IP, IPv6, IPv46, load_layer


class PayloadFinder(object):
    """This utility class finds known protocols that are included in a payload
    to define the actual payload of a message that should get reversed and to
    get additional context information.
    This might be handy in cases where the protocol is on a low layer (i.e.
    layer 2) and it is known that internet traffic (i.e. HTTP GET requests) are
    encapsulated. This class should identify and cut off this underlying traffic.
    """
    # TODO example usage above

    def __init__(self, known_IPs=set(), known_MACs=set()):
        self.known_IPs = known_IPs
        self.known_MACs = known_MACs
        pass

    @typeCheck(list, float)
    def _offsetCandidates(self, messages, separator=0.2):
        """Create a dict of possible payload offsets based on small messages and return list of
        biggest messages.

        We cluster all messages based on their size. Assuming that smaller messages probably have
        no payload in it, we might be lucky and find the typical header offset (=the size of small
        messages). We should try these offset candidates for the bigger messages that actually
        contain a payload. Thus, we return the biggest messages and a dict of possible offsets for
        the payload of this big messages.

        The separator defines where we separate "big" and "small" messages for this metric (e.g.
        0.2 will return the biggest 20% messages and return the sizes of the 80% small messages as
        offsets).
        """

        candidates = {}
        testMessages = []

        # create cluster based on message sizes
        cluster = Format.clusterBySize(messages)

        # create dict {offset candidate: occurences} of all sizes below separator
        for i in range(0,int(separator * len(cluster))):
            any, candidate = cluster[i].name.split('_')
            candidates[int(candidate)] = 0

        # create list of all messages of size above separator
        for i in range(int(separator * len(cluster)), len(cluster)):
            testMessages.extend(cluster[i].messages)

        return candidates, testMessages

    @typeCheck(dict,list,int,bool,bool)
    def _testOffsets(self, offsets, messages, msgsToTest=50, debug=False, omit_ether=False):
        # TODO A description would be great

        load_layer("http")
        load_layer("dns")
        load_layer("tls")
        load_layer("dhcp")

        def runTest(msgs, protos):
            """Try for all given messages if any protocol included in protos can be found.
            At first we try the known/given offsets, beginning by the most used. If these fail,
            we try all possible offsets (bytewise). To limit processing time, we only try for
            msgsToTest messages.
            """

            # assume all message have no payload, remove below if payload found
            nopayload = msgs.copy()

            # counter for messages in a row for which we did not found an offset
            notFoundCnt = 0

            def tryAndStore(packet):
                """Check if any protocol of protos is included in packet.
                If new IPs or MACs are found, store these in self.known_IPs/self.known_MACs
                Returns True if protocol was found, False if none was found or false positive is
                likely
                """

                # check for protocols in protos
                if any(proto in packet for proto in protos):

                    # only trust layer3/2 parsing if known IP/MAC is involved
                    if IP in protos and IP in packet and \
                            not packet[IP].src in self.known_IPs and \
                            not packet[IP].dst in self.known_IPs:
                        return False # maybe a false positive
                    if IPv6 in protos and IPv6 in packet and \
                            not packet[IPv6].src in self.known_IPs and \
                            not packet[IPv6].dst in self.known_IPs:
                        return False # maybe a false positive
                    if Ether in protos and \
                            not packet[Ether].src in self.known_MACs and \
                            not packet[Ether].dst in self.known_MACs:
                        return False # maybe a false positive

                    # build sets of known IPs and MACs based on found payloads
                    if IP in packet:
                        self.known_IPs.add(packet[IP].src)
                        self.known_IPs.add(packet[IP].dst)
                    if IPv6 in packet:
                        self.known_IPs.add(packet[IPv6].src)
                        self.known_IPs.add(packet[IPv6].dst)
                    if Ether in packet:
                        self.known_MACs.add(packet[Ether].src)
                        self.known_MACs.add(packet[Ether].dst)

                    return True # We found a protocol and/or new a IP/MAC

                else:
                    return False # we did not found a protocol

            # start with biggest messages
            for m in sorted(msgs, key=lambda x: len(x.data), reverse=True):

                not_found = True

                # most used offsets are tried first
                for offset in sorted(offsets, key=offsets.get, reverse=True):

                    # create scapy packet based on current offset
                    # FIXME you could try IP only and test Ether if this was successful to avoid this flag and thus generalize this function
                    if omit_ether:
                        if offset > len(m.data)-40: # at least 40 bytes of IPv6 Header
                            break # next message please!
                        packet = IPv46(m.data[offset:])
                    else:
                        if offset > len(m.data)-14: # at least 14 bytes of Ethernet Header
                            break # next message please!
                        packet = Ether(m.data[offset:])

                    if tryAndStore(packet):
                        offsets[offset]+=1
                        nopayload.remove(m) # remove from nopayload list
                        not_found = False
                        break # good offset found, next message please!
                    else:
                        continue # did not found a protocol, try next offset

                # if known offsets did not work, try all possible offset variants instead
                if not_found is True:

                    for offset in range(1, len(m.data)):
                        if offset not in offsets:

                            # create scapy packet based on current offset
                            if omit_ether:
                                if offset > len(m.data)-40: # at least 40 bytes of IPv6 Header
                                    break # next message please!
                                packet = IPv46(m.data[offset:])
                            else:
                                if offset > len(m.data)-14: # at least 14 bytes of Ethernet Header
                                    break # next message please!
                                packet = Ether(m.data[offset:])

                            if tryAndStore(packet):
                                offsets[offset] = 1
                                nopayload.remove(m) # remove from nopayload list
                                not_found = False
                                break # good offset found, next message please!
                            else:
                                continue # did not found a protocol, try next offset

                    if not_found:
                        notFoundCnt += 1

                if notFoundCnt > msgsToTest:
                    break

            return nopayload

        def sortOffsets(offsets, clean=False):
            sorted_offsets = {}
            for offset in sorted(offsets, key=offsets.get, reverse=True):
                if clean:
                    sorted_offsets[offset] = 0
                else:
                    sorted_offsets[offset] = offsets[offset]
            return sorted_offsets


        # try offsets for all messages to find payload, remember messages without payload 
        if debug:
            print("\nTesting possible offsets for payloads...")
        nopayload = runTest(messages, [DNS, HTTP, TLS, DHCP])

        # try messages without payload again, now for layer3 with known IPs
        nopayload = runTest(nopayload, [IP, IPv6])

        # try messages without payload again, now for layer2 with known MACs
        # TODO is looking for ARP an option?
        if not omit_ether:
            nopayload = runTest(nopayload, [Ether])

        # most used offset first on next run
        offsets = sortOffsets(offsets, clean=True)

        # try all messages again, now for layer2 with known MACs only
        if omit_ether:
            nopayload = runTest(messages, [IP, IPv6])
        else:
            nopayload = runTest(messages, [Ether])

        offsets = sortOffsets(offsets)

        # announce results
        if debug:
            if offsets:
                print("\nPayload offsets found:")
                self._printOffsets(offsets)
            else:
                print("\nNo payload offsets found!")
            if nopayload:
                print("\nThere was NO payload found for {} messages.".format(len(nopayload)))

        # create simple list of successful offsets instead of the current dict
        goodOffsets = []
        for offset,findings in offsets.items():
            if findings > 0:
                goodOffsets.append(int(offset))

        return goodOffsets

    def _parsePayloads(self, messages, offsets, omit_ether=False):
        """Uses the offsets to parse messages
        """
        # TODO more explanation please!

        parsed_messages = []

        for m in messages:

            if isinstance(m, L2NetworkMessage):
                new_m = WithPayloadMessage(m.data, m.date, m.l2Protocol)
            else:
                new_m = WithPayloadMessage(m.data, m.date)
            new_m.metadata = m.metadata

            for offset in offsets:

                if omit_ether:
                    if offset > len(m.data)-40: # at least 40 bytes of IPv6 Header
                        break # next message please!
                    packet = IPv46(m.data[offset:])
                else:
                    if offset > len(m.data)-14: # at least 14 bytes of Ethernet Header
                        break # next message please!
                    packet = Ether(m.data[offset:])

                offset_is_fine = False

                # check parsed MAC addresses to prevent false positives
                if Ether in packet:
                    if packet[Ether].src in self.known_MACs or packet[Ether].dst in self.known_MACs:
                        offset_is_fine = True

                # check parsed IP addresses to prevent false positives
                if IP in packet:
                    if packet[IP].src in self.known_IPs or packet[IP].dst in self.known_IPs:
                        offset_is_fine = True

                if IPv6 in packet:
                    if packet[IPv6].src in self.known_IPs or packet[IPv6].dst in self.known_IPs:
                        offset_is_fine = True

                if offset_is_fine: # parsing seems to be fine

                    new_m.payload = packet # store parsed scapy packet
                    new_m.payload_data = m.data[offset:] # store bytes

                    # store additional information based on parsed scapy packet
                    # TODO Not sure which and if needed in following processes

                    new_m.data = m.data[:offset] # cut off payload for good

                    break # offset found, stop trying others
                else:
                    continue # try another offsets

            parsed_messages.append(new_m)

        return parsed_messages

    def _printOffsets(self, offsets, gt0=True):
        # only print offsets with values > 0
        if gt0:
            print("\n<offset>: <findings>")
            for offset, occurences in offsets.items():
                if occurences > 0:
                    print(str(offset) + ': ' + str(occurences))
        # print all offsets (you do not really need this function to do so though)
        else:
            print(offsets)

        return

    @typeCheck(list)
    def findPayload(self, messages, separator=0.2, debug=False, omit_ether=False):
        """This method returns the list of messages with reduced payload if known protocols were
        found in the old payload.
        """
        # TODO examples

        # create a list of candidate payload offsets and test messages based on message sizes
        candidates, testMessages = self._offsetCandidates(messages, separator)

        # find payload offsets by trying the candidates on message set
        offsets = self._testOffsets(offsets=candidates, \
                                    messages=testMessages, \
                                    debug=debug, \
                                    omit_ether=omit_ether)

        # cutoff payloads and parse their contents
        parsed_messages = self._parsePayloads(messages, offsets, omit_ether)

        return parsed_messages
