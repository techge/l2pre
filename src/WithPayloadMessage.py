# Based on https://github.com/netzob/netzob/blob/49ee3e5e7d6dce67496afd5a75827a78be0c9f70/netzob/src/netzob/Model/Vocabulary/Messages/L3NetworkMessage.py

# external import
from scapy.all import Packet

# netzob import
from netzob.Common.Utils.Decorators import typeCheck
from netzob.Model.Vocabulary.Messages.L2NetworkMessage import L2NetworkMessage


class WithPayloadMessage(L2NetworkMessage):
    """Definition of a message with payload that can be parsed
    """

    def __init__(self,
                 data,
                 date,
                 l2Protocol=None,
                 l2SourceAddress=None,
                 l2DestinationAddress=None,
                 payload=None,
                 payload_data = None):
        super().__init__(
                 data,
                 date,
                 l2Protocol=l2Protocol,
                 l2SourceAddress=l2SourceAddress,
                 l2DestinationAddress=l2DestinationAddress)
        self.payload = payload
        self.payload_data = payload_data

    @property
    def payload(self):
        """The payload of the messages that is encapsulated by the protocol

        :type: Ether
        """
        return self.__payload

    @payload.setter
    @typeCheck(Packet)
    def payload(self, payload):
        self.__payload = payload

    @property
    def source(self):
        """The name or type of the source which emitted
        the current message

        :type: str
        """
        return str(self.l2SourceAddress)

    @property
    def destination(self):
        """The name or type of the destination which received
        the current message

        :type: str
        """
        return str(self.l2DestinationAddress)
