# Documentation of test cases

This folder contains pcapng files captured during a session with Siemens Scalance W700 devices using the iPCF feature.

Some requests where produced on a laptop connected to a Scalance W700 device working as client. This was done via [the requests.sh script](../requests.sh) to produce payload content.

|---------|---------|---------|------------------|------------------|---------------|---------|
| Testno. | clients | channel | cycle time in ms | protocol support | scanning Mode | iPCF-LF |
| 1 | 1 | 157 | 16 | Ethernet/IP | All | disabled |
| 2 | 1 | 161 | 16 | Ethernet/IP | All | disabled |
| 3 | 1 | 157 | 32 | Ethernet/IP | All | disabled |
| 4 | 1 | 157 | 16 | PROFINET | All | disabled |
| 5 | 2 | 157 | 16 | Ethernet/IP | All | disabled |
| 6 | 1 | 157 | 16 | Ethernet/IP | Next | disabled |
| 7 | 1 | 157 | 16 | Ethernet/IP | All | enabled |
|---------|---------|---------|------------------|------------------|---------------|---------|

All files have been filtered (only type 3 frames)

Thus, the following variables are currently considered in the testfiles:
* amount of connected clients
* channel in use
* iPCF cycle time in ms
* protocol support
* scanning mode
* iPCF-LF (legacy free)

### Some output after setting config

Automatically enabled by choosing iPCF (on AP) (as announced by popup window):

Use selected data rates only - enabled
Data Rate / Basic 12.0 [Mbps] - enabled
MCS Index 2 - enabled
Beacon Interval - 1000 [ms]
Fragmentation Length Threshold - 2346 [Bytes]
RTS/CTS Threshold - 2346 [Bytes]
HW Retries - 8
A-MPDU - disabled
A-MSDU - disabled
HT Channel Width - 20 [MHz]
Guard Interval - 800 [ns]
AP Communication within own VAP - disabled
AP Communication with other VAP - disabled
AP Communication with Ethernet - enabled
Encryption - disabled


Automatically enabled by choosing iPCF (on Client) (as announced by popup window):

Roaming Threshold - Medium
Fragmentation Length Threshold - 2346 [Bytes]
RTS/CTS Threshold - 2346 [Bytes]
HW Retries - 8
A-MPDU - disabled
A-MSDU - disabled
Encryption - disabled
MAC Mode - Layer 2 Tunnel
