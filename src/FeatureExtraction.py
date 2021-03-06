# system import
from binascii import unhexlify
import copy
from zlib import crc32, adler32

# nemere import
from nemere.utils.baseAlgorithms import ngrams

# netzob import
from netzob.Common.Utils.Decorators import typeCheck
from netzob.Inference.Vocabulary.EntropyMeasurement import EntropyMeasurement
from netzob.Inference.Vocabulary.FormatOperations.FieldOperations import FieldOperations
from netzob.Model.Vocabulary.Field import Field
from netzob.Model.Vocabulary.Symbol import Symbol
from netzob.Model.Vocabulary.Types.Raw import Raw

# internal import
from WithPayloadMessage import WithPayloadMessage
from utils import printFields


class FeatureExtraction(object):
    """This utility class contains all methods to extract features based on context information and
    known information. It can detect sequences and checksums as well.
    """

    @typeCheck(list, set)
    def __init__(self, messages_list):
        self.messages_list = messages_list
        self.symbol = Symbol()
        pass


    @typeCheck(Symbol, dict)
    def _insertFields(self, symbol, to_insert): # TODO put into utils
        """Inserts multiple fields to specific positions. Merges identical (=similar name) fields
        that are neighbors.

        :param symbol: symbol in which the fields get inserted
        :type symbol: :class:`netzob.Model.Vocabulary.Symbol`
        :param to_insert: dict of form {position_to_insert: (field_domain, field_name)}
        :type dict:
        """

        insert_prev = 0
        for pos, (domain, name) in to_insert.items():

            # if next entry belongs to same field (name), remember to insert next time
            if pos+1 in to_insert.keys():
                domain_next, name_next = to_insert[pos+1]
                if name == name_next:
                    insert_prev += 1
                continue

            # construct a bigger field that contains previous fields as well
            if insert_prev:
                domain_size = 0
                # calculate size of merged fields
                for i in range(insert_prev, -1, -1):
                    (domain, name) = to_insert[pos-i]
                    _, size = domain.size
                    domain_size += int(size/8)
                new_field = self._insertField(symbol, pos-insert_prev, Raw(nbBytes=domain_size))
                new_field.name = name
                insert_prev = 0

            # just insert single field
            else:
                new_field = self._insertField(symbol, pos, domain)
                new_field.name = name


    @typeCheck(Symbol, int, object)
    def _insertField(self, symbol, insert_pos, new_field_domain): # TODO put into utils
        """Inserts a field to a specific position. The new field replaces previously used space of
        other field(s) by firstly analysing the given fields. That is to say, this method tries to
        keep the overall size values of fields stable, but may ignores the domain info of the old
        fields (it just creates raw bytes fields).
        """

        new_fields = []

        if symbol.fields is None or new_field_domain is None:
            raise TypeError("Fields and field domain can not be None")

        # calculate needed size of field to insert
        _, new_field_size = (int(bits/8) for bits in new_field_domain.size)

        # auxiliary function to calculate min size value of field
        def updateMinsize(mins, size):
            if mins - size > 0:
                mins -= size
            else:
                mins = 0
            return mins

        # auxiliary variables
        fo = FieldOperations() # object for replacing fields
        curr_size = 0

        # field can be of fixed size or variable size; especially fields that might be not present
        # needs to keep track of, parsing errors will occur otherwise
        # we are doing are simple sanity check here, based on size of smallest message
        smallest_msg_len = min([len(x.data) for x in symbol.messages])
        if insert_pos >= smallest_msg_len:
            force_optional = True
        else:
            force_optional = False
        field_is_optional = False

        # iterate through fields to find field which needs to get split up for our new field
        for i,oldField in enumerate(symbol.fields):
            minsize, maxsize = (int(bits/8) for bits in oldField.domain.dataType.size)

            if curr_size + maxsize > insert_pos: # new field should be inserted here
                if minsize == 0:
                    field_is_optional = True

                new_domains = [] # list of new domains existing because of insertion

                # insert oldFields remainings (begin)
                if curr_size != insert_pos: # new field does not start at old field's beginning
                    size = insert_pos - curr_size
                    if field_is_optional and force_optional:
                        new_domains.append(Raw(nbBytes=(0, size)))
                    else:
                        new_domains.append(Raw(nbBytes=(size)))
                    minsize = updateMinsize(minsize, size)

                # insert our new field
                if field_is_optional and force_optional:
                    f = Field()
                    _, size = new_field_domain.size
                    new_domains.append(Raw(nbBytes=(0, int(size/8)))) # insert new field
                else:
                    new_domains.append(new_field_domain) # insert new field
                new_field_index = len(new_domains) - 1 # index of inserted field for return value

                # delete following fields if necessary
                while curr_size + maxsize < insert_pos + new_field_size: # new field spans >1 field
                    if oldField == symbol.fields[-1]: # we already reached the last field
                        break
                    i += 1
                    nextmins, nextmaxs = (int(bits/8) for bits in symbol.fields[i].domain.dataType.size)
                    minsize += nextmins
                    maxsize += nextmaxs
                    fo.replaceField(symbol.fields[i], []) # delete field

                # decreasing minsize only now, because field overflow wasn't done before
                minsize = updateMinsize(minsize, new_field_size)

                # insert oldFields remainings (end)
                if curr_size + maxsize > insert_pos + new_field_size: # some space left in old field
                    size_left = (curr_size + maxsize) - (insert_pos + new_field_size)
                    #minsize = updateMinsize(minsize, size_left)
                    if field_is_optional and force_optional:
                        new_domains.append(Raw(nbBytes=(0, size_left)))
                    else:
                        new_domains.append(Raw(nbBytes=(minsize,size_left)))

                new_fields = fo.replaceField(oldField, new_domains)
                break

            curr_size += maxsize # increase size for next loop level

        return new_fields[new_field_index] # return inserted field


    @typeCheck(list)
    def _addrEx(self, messages):
        """This method finds address fields by creating n-grams of 6 to 1 byte(s). A n-gram that
        appears on multiple, not overlapping positions within different message is probably a
        address. This method works on the following assumptions:
            * there are at least two address fields
            * there is actually a communication, a party is sometimes a sender, sometimes a receiver

        :param messages: list of messages
        :type list:
        :return: a symbol containing the address fields and empty fields otherwise
        :rtype: :class:`netzob.Model.Vocabulary.Symbol`
        """

        def searchForAddr(addr: str):
            addr_pos_cnt = {} # count how often a addr was seen at a position
            for m in messages:
                begin = 0
                addr_pos = m.data.find(addr, begin)
                while addr_pos >= 0:
                    if addr_pos in addr_pos_cnt.keys():
                        addr_pos_cnt[addr_pos]+=1
                    else: # create new dict entry if not already in the dict
                        addr_pos_cnt[addr_pos]=1
                    begin = addr_pos + 1
                    addr_pos = m.data.find(addr, begin)
            return addr_pos_cnt

        def evaluateAddrCertainty(addr_pos_cnt: dict, addr_len: int):
            if len(addr_pos_cnt) > 1 and len(addr_pos_cnt) < 5:
                prev_addr_position = None # position of previous address
                next_addr_positions = sorted(addr_pos_cnt.keys()) # following positions of addresses
                for addr_pos in sorted(addr_pos_cnt.keys()):
                    next_addr_positions.remove(addr_pos)
                    # make sure there is no overlapping with other address appearances
                    # if overlappting is found, we do not trust this address and return False
                    if (prev_addr_position and prev_addr_position + addr_len > addr_pos) or \
                            (next_addr_positions and next_addr_positions[0] < addr_pos + addr_len):
                        return False
                    prev_addr_position = addr_pos
                return True
            else:
                return False

        def createFields(addr_positions: list, addr_len: int):
            max_len = max(len(m.data) for m in messages)
            fields = []
            i = 0
            for pos in addr_positions:
                if pos > i: # there are some bytes that are no address field, so filling up
                    fields.append(Field(Raw(nbBytes=pos - i))) # add field for bytes in between
                new_field = Field(Raw(nbBytes=addr_len))
                new_field.name = "Address"
                fields.append(new_field)
                i = pos + addr_len
            # there are still bytes left after last address field, so create another field for these
            if i < max_len:
                fields.append(Field(Raw(nbBytes=(0,max_len))))
            return Symbol(fields, messages)


        # we try n-gram of 6 to 1 Byte(s) as address candidates. Those candidates that appear
        # at different positions and do not overlap are probably cool
        ret_symbol = None
        for addr_len in range(6,1,-1):
            for addr_cand in ngrams(messages[0].data, addr_len):
                addr_pos_cnt = searchForAddr(addr_cand)
                if evaluateAddrCertainty(addr_pos_cnt, addr_len):
                    addr_positions = sorted(addr_pos_cnt.keys())
                    ret_symbol = createFields(addr_positions, addr_len)
                    # TODO we are satisfied with the very first successful finding, might be worth
                    # to find another heuristic to evaluate the correctness. The reason for the
                    # current approach is the fact that i) it works and ii) addresses of multiple
                    # bytes will produce multiple, following fields that look fine, but usually
                    # it should be the first that is actually correct
                    break
            if ret_symbol is not None: # there's nothing to do here anymore
                break

        if ret_symbol is None:
            raise ValueError("Did not find any address field, we can not proceed :(")

        return ret_symbol


    @typeCheck(Symbol, Field)
    def _clusterByKeyField(self, symbol, keyField):
        """Cluster all messages of symbol based on a field. Returns a list of symbols.
        """

        if not symbol.messages:
            raise ValueError("No messages were given, can not proceed")

        cluster = []

        # calculate position of field in message
        minsize = maxsize = 0
        for field in symbol.fields:
            _, maxsize = field.domain.dataType.size
            if field == keyField:
                maxsize = minsize + maxsize
                break
            minsize += maxsize

        # for every possible value in keyField we sort the corresponding messages in these buckets
        for val in set(self._getValuesQuick(symbol, keyField)):
            newMessages = []

            for m in symbol.messages:
                if m.data[int(minsize/8):int(maxsize/8)] == val: # maxsize as integer byte value
                    newMessages.append(m)

            if not newMessages:
                raise ValueError("No messages matching this field value, something's wrong.")

            newSymbol = copy.deepcopy(symbol) # TODO implement accurate copy function in netzob
            newSymbol.name = "Symbol_" + val.hex()
            newSymbol.messages = newMessages
            cluster.append(newSymbol)

        return cluster # list of Symbols based of keyField value

    @typeCheck(Symbol, Field)
    def _getValuesQuick(self, symbol, field):
        """A quicker and naive getValues() function as netzob's Field.getValues() is quite slow...

        :param symbol: symbol in which field appear
        :type symbol: :class:`netzob.Model.Vocabulary.Symbol`
        :param field: field whose values are of interest
        :type field: :class:`netzob.Model.Vocabulary.Field`
        :return: a list detailling all the values a field takes.
        :rtype: a :class:`list` of :class:`str`
        :raises: :class:`netzob.Model.Vocabulary.AbstractField.AlignmentException` if an error occurs while aligning messages
        """

        # calculate byte position of the field within the symbol
        start = end = 0
        for f in symbol.fields:
            min_size, max_size = f.domain.dataType.size
            if f == field:
                start = end # start is old fields end
                end += int(max_size/8)
                break
            if min_size != max_size:
                printFields(symbol)
                raise ValueError("_getValuesQuick() only works with Symbols that only have " + \
                        "fixed-size fields, use Field.getValues() instead.")
            end += int(max_size/8)

        # retrieve list of message data
        data = [message.data for message in field.messages]

        # get field values at calculated position and add them to list
        values = []
        for dat in data:
            value = dat[start:end]
            values.append(value)

        return values


    @typeCheck(Symbol)
    def _seqEx(self, symbol):
        """Detect sequence fields. If fields are increasing most of the time, we can assume that it
        is a sequence field. The implementation is based on the following observations:

            * the most significant byte (MSB) of a two byte field only overflows (previous value is
            smaller then current value), if the neighbor byte (least significant byte, LSB) is
            increasing at the same time, and previous value seldom equals the current value
            * the LSB of a two byte field only increases, if the neighbor (MSB) is decreasing
            (overflow of MSB), the LSB is nearly never decreasing (overflow is seldom) and the
            previous value equals very often the current value
            * if it is no MSB or LSB of a two-byte sequence, but still often inceasing and
            the previous value equals the current value only seldom, it is likely a one-byte
            sequence field

        As sequence fields are usually based on the sending source, we need to know address fields
        for this method to work.
        """

        if symbol.fields is None:
            raise TypeError("symbol.fields can not be None")

        # look how many address fields we have
        addr_field_index = []
        for field in symbol.fields:
            if field.name == "Address":
                addr_field_index.append(symbol.fields.index(field))

        # we depend on address addresses to evaluate certainty of sequence bytes
        if not addr_field_index:
            printFields(symbol)
            raise ValueError("No address field(s) found in field")

        if symbol.messages is None:
            raise TypeError("No messages were given, can not proceed")

        if len(symbol.messages) < 50: # sample size too small
            return

        # Decide which address to use as sender address (which is the one counting up the seq)
        if len(addr_field_index) == 1:
           addrs = self._getValuesQuick(symbol, symbol.fields[addr_field_index[0]])
        else: # just assume second is source (just a good guess, but doesn't matter much anyway)
            addrs = self._getValuesQuick(symbol, symbol.fields[addr_field_index[1]])

        # create set of source addresses
        src_addrs = set(addrs)

        # create entropy list over all messages
        e_measure = EntropyMeasurement()
        entropies = [entr for entr in e_measure.measure_entropy(symbol.messages)]

        skip_next = False
        to_insert = {} # fields to insert into symbol {pos_to_insert: (field_domain, field_name)}

        # here we just step through every byte position of max len of symbol.messages
        # entropy value of current position might be used for Checksum check below, it's unused otherwise
        for pos,e in enumerate(entropies):

                if pos == 0: # sequences usually do not start at 0
                    continue

                if skip_next: # last loop iteration found two fields at once, thus skip this step
                    skip_next = False
                    continue

                curr_eq_prev_cnt = 0
                curr_less_prev_cnt = 0
                left_neighbor_LSB = True
                left_neighbor_MSB = True
                right_neighbor_LSB = True
                right_neighbor_MSB = True

                for src_addr in src_addrs:

                    first_val = True # need to set prev_vals first

                    # step through all messages of a specific source
                    for i, data in enumerate(addrs):
                        if data == src_addr:

                            if pos >= len(symbol.messages[i].data): # message too short!
                                break

                            if first_val: # set prev_vals now and step loop
                                l_prev_val = symbol.messages[i].data[pos-1]
                                prev_val = symbol.messages[i].data[pos]
                                if pos+1 >= len(symbol.messages[i].data):
                                    r_prev_val = 0
                                else:
                                    r_prev_val = symbol.messages[i].data[pos+1]
                                first_val = False
                                continue

                            # set curr_vals
                            l_curr_val = symbol.messages[i].data[pos-1]
                            curr_val = symbol.messages[i].data[pos]
                            if pos+1 >= len(symbol.messages[i].data): # prevent out-of-bound error
                                r_curr_val = 0
                            else:
                                r_curr_val = symbol.messages[i].data[pos+1]

                            # value unchanged
                            if curr_val == prev_val :
                                curr_eq_prev_cnt += 1

                                if l_curr_val < l_prev_val:
                                    left_neighbor_MSB = False
                                if r_curr_val < r_prev_val:
                                    right_neighbor_MSB = False

                            # value increased
                            elif curr_val > prev_val:

                                if l_curr_val >= l_prev_val :
                                    left_neighbor_MSB = False
                                if r_curr_val >= r_prev_val :
                                    right_neighbor_MSB = False

                            # value decreased (=possible overflow)
                            else:
                                curr_less_prev_cnt += 1

                                if l_curr_val <= l_prev_val:
                                    left_neighbor_LSB = False
                                if r_curr_val <= r_prev_val:
                                    right_neighbor_LSB = False

                            # set prev_val for next loop step
                            prev_val = curr_val
                            l_prev_val = l_curr_val
                            r_prev_val = r_curr_val


                # calculate percentages
                curr_eq_prev = curr_eq_prev_cnt/len(symbol.messages)
                curr_less_prev = curr_less_prev_cnt/len(symbol.messages)

                if first_val: # empty loop step, thus do not evaluate values
                    pass
                # merge byte on current position with left byte (=2-bytes sequence field)
                if (left_neighbor_MSB and curr_eq_prev < 0.95 and curr_less_prev < 0.1) or \
                        (left_neighbor_LSB and curr_eq_prev < 0.25):
                    to_insert.update({pos-1: (Raw(nbBytes=2), "SEQ")})
                # merge byte on current position with right byte (=2-bytes sequence field)
                elif (right_neighbor_MSB and curr_eq_prev < 0.95 and curr_less_prev < 0.1) or \
                        (right_neighbor_LSB and curr_eq_prev < 0.25):
                    to_insert.update({pos: (Raw(nbBytes=2), "SEQ")})
                    skip_next = True # we already know that the next byte is a sequence byte
                # single-byte sequence field
                elif curr_eq_prev < 0.25 and curr_less_prev < 0.1:
                    to_insert.update({pos: (Raw(nbBytes=1), "SEQ")})
                else:
                    # it is no sequence field, but the entropy is high, might be worth noting...
                    if e > 7.0:
                        to_insert.update({pos: (Raw(nbBytes=1), "High_entropy")})

        # insert new fields to symbol
        self._insertFields(symbol, to_insert)

        # test if last protocol field is a checksum (if marked "high entropy" and has four bytes)
        # actually, it is symbol.fields[-2], because last field of the symbol is payload field
        # TODO may needs improvement, e.g. if protocol never includes a payload, this probably fails
        # furthermore, checksum that is behind a payload is currently cut off and thus lost :(
        if len(symbol.fields) >= 2 and \
                symbol.fields[-2].name == "High_entropy" and \
                symbol.fields[-2].domain.dataType.size == (32, 32):

            # we want to test some messages, to prevent malformed packets, but 10 shall be enough
            msgs_to_test = 10 if 10 < len(symbol.messages) else len(symbol.messages)
            for i in range(0, msgs_to_test):

                # divide potential checksum and the rest of the data
                checksum_value = symbol.messages[i].data[-4:]
                data_without_checksum = symbol.messages[i].data[:-4]

                # calculate well-known checksums TODO add more commonly known checksums
                crc32_result = crc32(data_without_checksum).to_bytes(4, byteorder='little')
                adler32_result = adler32(data_without_checksum).to_bytes(4, byteorder='little')

                if checksum_value == crc32_result:
                    symbol.fields[-2].name = "crc32"
                    break
                elif checksum_value == adler32_result:
                    symbol.fields[-2].name = "adler32"
                    break
                else:
                    # it still pretty much *looks* like a checksum...
                    symbol.fields[-2].name = "Checksum?"

        return


    @typeCheck(Symbol, Symbol)
    def _fieldsAreSimilar(self, sym1, sym2):
        """Compares two symbols for the following aspects:
            * name of the symbols should be equal
            * len on fields should be equal
            * size of each field should be equal (except last field that can differ)
        """

        fields1 = sym1.fields
        fields2 = sym2.fields

        # despite the name, we are only checking size here really...
        def domainsAreEqual(f1, f2):
            if f1.domain.dataType.size == f2.domain.dataType.size:
                return True
            else:
                return False

        if sym1.name != sym2.name:
            return False

        if len(fields1) != len(fields2):
            return False

        field_cnt = 0
        for field1, field2 in zip(fields1, fields2):
            field_cnt += 1
            if not domainsAreEqual(field1, field2) and field_cnt < len(fields1):
                return False

        return True


    @typeCheck(Symbol, int)
    def _adaptLengthFields(self, sym):
        """Change length of (last) field of Symbol sym to fit min_len and max_len of messages
        """

        if sym.messages is None:
            raise ValueError("No messages were given, this shouldn't be the case")

        max_len = max(len(x.data) for x in sym.messages) # size of longest message
        min_len = min(len(x.data) for x in sym.messages) # size of shortest message
        mins = maxs = 0 # cumulated minimal and maximal size of fields

        for ifield, field in enumerate(sym.fields):
            newmin, newmax = field.domain.dataType.size
            newmin = int(newmin/8)
            newmax = int(newmax/8)
            mins += newmin
            maxs += newmax

            if mins > min_len: # message can be shorter than anticipated, adapt our protocol format
                mindiff = mins - min_len
                newmin -= mindiff
                field.domain.dataType.size = (newmin*8, newmax*8) # set new min size
                if field != sym.fields[-1]: # set all following fields to minsize zero
                    for i in range(ifield+1, len(sym.fields)):
                        _, s = sym.fields[i].domain.dataType.size
                        sym.fields[i].domain.dataType.size = (0, s) # set min to zero


            if maxs > max_len: # more space is "allocated" by format than needed
                # we are not at last field, but already reached max length -> delete unneeded fields
                if field != sym.fields[-1]:
                    fo = FieldOperations()
                    for i in range(len(sym.fields)-1, ifield, -1):
                        fo.replaceField(sym.fields[i], [])

                # now we need to change the size of (new) last field
                # set newmax
                maxdiff = maxs - max_len
                newmax -= maxdiff
                # set newmin
                if mins <= min_len:
                    mindiff = min_len - mins
                    if newmin + mindiff < newmax:
                        newmin += mindiff
                    else:
                        newmin = newmax
                if newmax <= 0: # delete empty field
                    fo = FieldOperations()
                    fo.replaceField(field, [])
                else:
                    field.domain.dataType.size = (newmin*8, newmax*8) # set new size values

                break # we are done here...
        return


    @typeCheck(list)
    def _basicFeatureEx(self, messages_list):
        """Analyze basic feature (Address, SEQ fields) of messages and cluster messages by type.

        :param messages_list: list of lists with messages
        :type list:
        :return: list of clusters corresponding to list items
        """

        analyzed_msgs = []

        # for every message set, try to find address and SEQ fields
        # the messages are clustered by first field (bitmask) and stored in analyzed_msgs
        for msgs in messages_list:

            # try to find address fields
            symbol = self._addrEx(msgs)

            # assuming first unidentified field is defining message type,
            # we are clustering the messages by type
            # TODO make an *educated guess* which field is defining message type instead of assuming it
            for i_field, field in enumerate(symbol.fields):
                if field.name == "Field":
                    # TODO might be a big fat field at the end, that would be bad... might
                    # cut off rest if bigger that usual frame field in this case?
                    field.name = "Frame_type"
                    cluster = self._clusterByKeyField(symbol, symbol.fields[i_field])
                    break

            # try to find sequence field(s)
            for c in cluster:
                c.orig_messages = list(c.messages)
                self._seqEx(c)

            analyzed_msgs.append(cluster)

        return analyzed_msgs


    @typeCheck(Symbol)
    def _deduplicate(self, sym):
        """Deduplicate the list of messages found in a given symbol by zeroing SEQ and Checksum fields.
        Information might get lost, but the amount of messages can get reduced significantly which
        makes further analysis much faster and easier.
        """

        fields_to_deduplicate = [
                "SEQ",
                "crc32",
                "adler32",
                "Checksum?",
                ]

        # find positions of SEQ and Checksum fields
        field_positions = []
        begin_pos = end_pos = 0
        for field in sym.fields:
            _, end_pos = field.domain.dataType.size
            if field.name in fields_to_deduplicate:
                # store byte position in message
                field_positions.append((int(begin_pos/8), int((begin_pos+end_pos)/8)))
            begin_pos += end_pos

        # set SEQ and Checksum field of all messages to zero
        for m in sym.messages:
            for start, end in field_positions:
                m.data = bytes(m.data[:start] + b"\x00"*(end-start) + m.data[end:])

        # remove all non-unique messages
        deduplicated_data = set()
        new_messages = []
        for m in sym.messages:
            if m.data not in deduplicated_data:
                deduplicated_data.add(m.data)
                new_messages.append(m)

        # set sym.messages to deduplicated list of messages
        sym.messages = new_messages
        sym.dedup_messages = list(sym.messages)

        return


    @typeCheck(list)
    def _contextFeatureEx(self, cluster_list):
        """Find differences in context information that correlate with differences in messages to
        enrich field information. The given messages need to have been enriched with context
        information given in message.metadata variable.

        :param cluster_list: list of clustered messages, each item belonging to a pcap
        :type list:
        :return: clustered messages from all pcaps with enriched field information based on context
        """

        def mergeSymbols(sym_list: list):
            """Auxilliary function to merge a list of symbols - if possible - otherwise multiple
            symbols are returned.
            """
            merged_sym = []
            sym_cnt = 1
            for sym in sym_list:
                if not merged_sym:
                    merged_sym = [sym]
                # are the fields of the current symbol similar to the other sym?
                elif self._fieldsAreSimilar(merged_sym[0], sym):
                    # add messages to existing symbol
                    merged_sym[0].messages.extend(sym.messages)
                    merged_sym[0].orig_messages.extend(sym.orig_messages)
                # the symbols differ, we need to add the symbol instead of merging
                else:
                    # TODO we might compare multiple syms, if most are similar, wie dismiss the
                    # differing one
                    print("Warning: Created symbols of different traces did not match, " + \
                            "that is {}. \n".format(sym.name) + \
                            "We added both, so you might see which is correct yourself.")
                    sym.name = sym.name + "-" + str(sym_cnt) # add number to name
                    sym_cnt += 1
                    merged_sym.append(sym)
            return merged_sym

        # put all symbols of the separate clusters in a single dict - symbolname: [symbols]
        symbol_dict = {}
        for cluster in cluster_list:
            for symbol in cluster:

                if symbol.fields is None:
                    raise ValueError("symbol.fields can not be None")

                if symbol.messages is None:
                    raise ValueError("No messages were given, can not proceed")

                if symbol.name not in symbol_dict.keys():
                    symbol_dict[symbol.name] = [symbol]
                else:
                    symbol_dict[symbol.name].append(symbol)

        # create entropies and compare values per symbol type
        frametypes_cluster = [] # list of merged symbols that will be returned at last
        for sym_list in symbol_dict.values():

            # avoid false possitives for symbols with only a few messages (unreliable entropy value)
            if all(len(sym.messages) < 2 for sym in sym_list): # TODO re-evaluate threshold
                # nevertheless, we will add them to our frametypes_cluster...
                merged_sym = mergeSymbols(sym_list)
                for sym in merged_sym:
                    frametypes_cluster.append(sym)
                continue

            # create entropy list
            entropy_list = []
            for sym in sym_list:
                if len(sym.messages) == 1:
                    entropies = [0.0] * len(sym.messages[0].data)
                else:
                    e_measure = EntropyMeasurement()
                    entropies = [entr for entr in e_measure.measure_entropy(sym.messages)]
                entropy_list.append(entropies)

            # go through entropy per byte position
            feature_per_position = {} # dict of position: [features_this_byte_depends_on]
            for i, t in enumerate(zip(*entropy_list)):

                # entropy on a byte position is zero for every context...
                if set(t) == {0.0}:

                    # ... but are the values at this position always the same? Collecting values.
                    vals = {} # dict of value: [found metadatas]
                    for sym in sym_list:
                        if len(sym.messages[0].data) > i:
                            val = sym.messages[0].data[i]
                            meta = sym.messages[0].metadata
                            if val not in vals.keys():
                                vals[val] = [meta]
                            else:
                                vals[val].append(meta)
                        else:
                            break

                    # Values differ - context change may have caused the difference!
                    if len(vals) > 1:

                        # for each value, find context that does *not* change if value is constant
                        fixed_context = {} # value: {metadata that kept static between values}
                        for val, metadata_list in vals.items():
                            meta1 = {}
                            for meta2 in metadata_list:
                                if not meta1:
                                    meta1 = meta2
                                    continue
                                static_per_value = \
                                        [k for k in meta1 if k in meta2 and meta1[k] == meta2[k]] 
                                new_meta1 = {}
                                for key in static_per_value:
                                    new_meta1[key] = meta1[key]
                                meta1 = new_meta1
                            fixed_context[val] = meta1

                        # compare fixed contexts of the values with these of the others
                        # if the contents differ, we have a change that is likely to be connected/
                        # dependent on the contexts
                        context_changes = set()
                        meta1 = {}
                        for val, meta2 in fixed_context.items():
                            if not meta1:
                                meta1 = meta2
                                continue
                            diff_keys = [k for k in meta1 if k in meta2 and meta1[k] != meta2[k]]
                            meta1 = meta2
                            if diff_keys:
                                for key in diff_keys:
                                    context_changes.add(key)

                        # store results in intermediate variable to insert in fields later
                        if context_changes:
                            # give the field a proper name based on given metadata
                            if len(context_changes) > 1:
                                feat_str = ""
                                for feat in context_changes:
                                    feat_str += feat + ":"
                                feat_str = feat_str[:-1] # remove last colon from str
                            else:
                                feat_str = str(*context_changes)
                            feature_per_position.update({i: (Raw(nbBytes=1), feat_str)})

            # merge items of sym_list into a symbol
            merged_sym = mergeSymbols(sym_list)

            # insert features and add to frametypes_cluster
            for sym in merged_sym:
                # insert context information as fields of symbol
                self._insertFields(sym, feature_per_position)

                # add symbol to cluster
                frametypes_cluster.append(sym)

        if len(symbol_dict) > len(frametypes_cluster):
            raise ValueError("Merging symbols failed! There got {} symbols lost.".format(
                len(symbol_dict)-len(frametypes_cluster)))

        return frametypes_cluster

    #def _payloadInfoEx(self):
    #    # TODO
    #    return


    def execute(self):
        """Apply all detection methods at hand to the given messages.

        >>> features = FeatureExtraction.FeatureExtraction(messages)
        >>> cluster = features.execute()

        cluster contains all messages clustered by their first field.
        """
        # TODO enrich example with actual practical example :)

        print("\n> Find basic features in messages (Address, SEQ and Checksum fields)...")
        cluster_list = self._basicFeatureEx(self.messages_list)

        # we got multiple pcaps and probably different context, do some context analysis...
        if len(cluster_list) > 1:
            print("\n> Find features by comparing context information...")
            frametypes_cluster = self._contextFeatureEx(cluster_list)
        # just use single list item for next steps
        else:
            frametypes_cluster = cluster_list[0]

        # sort cluster by symbol.name to get reproducible exports
        frametypes_cluster.sort(key=lambda x: x.name)

        # make sure that length of last field equals length of biggest/smallest message
        for sym in frametypes_cluster:
            self._adaptLengthFields(sym)

        print("\n> Deduplicate messages...")
        for c in frametypes_cluster:
            self._deduplicate(c)

        # TODO does it make sense to merge cluster members to a single symbol (ideally self.symbol)
        # and return this instead?
        return frametypes_cluster


