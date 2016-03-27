import binascii
import csv

import re
from pcapfile import savefile
from pcapfile.protocols.linklayer.ethernet import Ethernet
from pcapfile.protocols.network.ip import IP


def extract_range(tcp_packet):
    pattern = re.compile('Range: bytes=([0-9]+)-([0-9]+)')
    for line in tcp_packet.split('\r\n'):
        match = re.match(pattern, line)
        if match is not None:
            return int(match.group(1)), int(match.group(2))
    return None


if __name__ == '__main__':
    input_file = '/media/crunch/Stuff/hannibal_dump/shark_dump_1459110596.pcap'
    pcap_file = open(input_file)
    pcap_data = savefile.load_savefile(pcap_file, verbose=True)

    csv_file = open('netflix_chunks.csv', 'w')
    writer = csv.DictWriter(csv_file, fieldnames=['chunk', 'timestamp'])
    writer.writeheader()
    for pkt in pcap_data.packets:
        pkt_ts = pkt.timestamp + pkt.timestamp_ms / 1000000.
        eth_frame = Ethernet(pkt.raw())
        try:
            ip_packet = IP(binascii.unhexlify(eth_frame.payload))
        except AssertionError:
            continue
        tcp_packet = binascii.unhexlify(ip_packet.payload)

        if 'GET' in tcp_packet and 'Range' in tcp_packet:
            res = extract_range(tcp_packet)
            if res is not None:
                writer.writerow({'chunk': res[1] - res[0], 'timestamp': pkt_ts})
    csv_file.close()
