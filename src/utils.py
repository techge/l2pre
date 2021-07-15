# system import
from os.path import isfile
from yaml import safe_load

# netzob import
from netzob.Import.PCAPImporter.all import PCAPImporter

def import_messages(files, importLayer=1):
    """Import pcap and context yaml files.

    :param files: direct filepath to .pcapng/.pcap files, .yaml files in same folder are imported
    :return: list of message list (each item contains a list of message of a pcap file)
    """

    messages = []

    # import all given files and store their messages
    for f in files:

        # import pcap
        new_messages = PCAPImporter.readFile(f, importLayer=importLayer).values()

        # look if a .yaml file exist for the current pcap file and load context information
        context = {}
        if isfile(f+'.yaml'):
            with open(f+'.yaml') as yaml_file:
                context = safe_load(yaml_file)

        # if context is available, store it as metadata in every message
        if context:
            for m in new_messages:
                m.metadata = context

        messages.append(new_messages)

    return messages

