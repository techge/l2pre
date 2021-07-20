# system import
from os.path import isdir
from shutil import copyfile
from time import strftime

# netzob import
from netzob.Export.WiresharkDissector.WiresharkDissector import WiresharkDissector

def exportPF(cluster):
    """Export inferred protocol information to folder 'reports'
    """

    # TODO something more than simple symbol print? Regex? Some bright idea?

    # create file name based on date and time
    fname = 'protocol_format_' + strftime("%Y-%m-%d_%H%M%S") + '.txt'

    # open file
    if isdir('reports'):
        with open('reports/' + fname, 'a+') as formatfile:
            formatfile.write("Protocol Format")
            for symbol in cluster:
                formatfile.write("\n\n{}: {} unique messages\n".format(symbol.name, \
                                                                       len(symbol.messages)))
                formatfile.write(str(symbol))

    print("\nProtocol format exported to \'reports/{}\'.".format(fname))

    return


def exportWiresharkDissector(cluster):
    """Export a Wireshark dissector written in lua (based on netzob exporter)
    """
    # FIXME

    # create file name based on date and time
    fname = 'wireshark_dissector_' + strftime("%Y-%m-%d_%H%M%S") + '.lua'

    # open file
    if isdir('reports'):
        WiresharkDissector.dissectSymbols(cluster,'reports/'+fname)

    print("\nWireshark dissector exported to \'reports/{}\'.".format(fname))

    return


def exportFuzz(cluster):
    """Export a template to be used for fuzzing attempts based on inferred protocol information
    """

    # create file name based on date and time
    new_template = 'reports/boofuzz_template_' + strftime("%Y-%m-%d_%H%M%S") + '.py'

    # open file
    if isdir('reports'):
        with open(new_template, 'a+') as template:

            # write import
            template.write("from boofuzz import Request, Block, Static, Bytes, Checksum\n\n")

            # write request for each symbol
            for symbol in cluster:

                symbol.encodingFunctions = [] # remove encoding function

                # start request
                template.write("{} = Request(children=(\n".format(symbol.name))
                intendation = "    "

                # FIXME depending on protocol there might be some bytes beforehand
                # e.g. for 802.11 packets we need a Radiotap header to inject these
                radiotap = b"\x00\x00\x08\x00\x00\x00\x00\x00"
                template.write("    Static(name=\"Radiotap\", " + \
                               "default_value={}),\n".format(str(radiotap)))

                # TODO there could be multiple Checksum fields in a message, but we assume only one at
                # the end here, would be nice to handle this differently
                if symbol.fields[-1].name == "Checksum":
                    template.write(intendation + "Block(\"Fields\", children=(\n")
                    intendation += "    "

                # go through all fields and write chunks
                mac_cnt = 1
                seq_cnt = 1
                other_field_cnt = 1
                for field in symbol.fields:

                    if field.name == "Frame":
                        primitive = "Static"
                        args = "name=\"" + field.name + "\""
                        # only one possible value per symbol
                        args += ", default_value={}".format(field.getValues()[0])

                    elif field.name == "MAC":
                        args = "name=\"" + "MAC-" + str(mac_cnt) + "\""
                        mac_cnt += 1
                        values = set(field.getValues())
                        if len(values) == 1:
                            primitive = "Static"
                            args += ", default_value=" + str(*values)
                        else:
                            primitive = "Group"
                            args += ", values=["
                            for val in values:
                                args += str(val) + ", "
                            args = args[:-1] # remove last colon
                            args += "]"

                    elif field.name == "SEQ":
                        primitive = "Bytes"
                        args = "name=\"" + "SEQ-" + str(seq_cnt) + "\""
                        seq_cnt += 1
                        args += ", default_value={}".format(field.getValues()[0])
                        _, maxs = field.domain.dataType.size
                        args += ", size=" + str(int(maxs/8))
                        args += ", fuzzable=False"

                    elif field.name == "Checksum" and field == symbol.fields[-1]:
                        break

                    # unknown field, fuzz it!
                    #elif field.name == "Field": TODO

                    # context-related field, define known values and fuzz TODO
                    else:
                        primitive = "Bytes"
                        args = "name=\"" + field.name + str(other_field_cnt) + "\""
                        other_field_cnt += 1
                        args += ", default_value={}".format(field.getValues()[0])
                        mins, maxs = field.domain.dataType.size
                        if mins == maxs:
                            args += ", size=" + str(int(maxs/8))
                        else:
                            args += ", max_length=" + str(int(maxs/8))

                    # write chunk
                    template.write(intendation + "{}({}),\n".format(primitive, args))

                if symbol.fields[-1].name == "Checksum":
                    intendation = intendation[4:]
                    template.write(intendation + ")),\n")
                    # add Checksum field now
                    primitive = "Checksum"
                    args = "name=\"" + field.name + "\""
                    args += ", block_name=\"Fields\""
                    # TODO get actual checksum function, currently we just assume popular crc32
                    args += ", algorithm=\"{}\"".format("crc32")

                    # write checksum chunk
                    template.write(intendation + "{}({}),\n".format(primitive, args))

                # close request
                template.write("))\n\n")

            # write list of all symbols for easier usage
            template.write("frames = [")
            for symbol in cluster:
                template.write("    " + symbol.name + ",\n")
            template.write("]")

    print("\nBoofuzz template exported to {}.".format(new_template))

    # copy to src/boofuzz_template.py as this is imported by src/fuzz.py
    if isdir('src'):
        active_template = 'src/boofuzz_template.py'
        copyfile(new_template, active_template)

    return
