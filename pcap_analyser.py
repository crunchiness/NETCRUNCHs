# -*- coding: utf-8 -*-
__author__ = 'crunch'
import binascii
import csv
from pcapfile import savefile
from pcapfile.protocols.network.ip import IP
from pcapfile.protocols.linklayer.ethernet import Ethernet
import sys


def parse(ip_packet):
    return {
        'v': ip_packet.v,
        'hl': ip_packet.hl,
        'tos': ip_packet.tos,
        'len': ip_packet.len,
        'id': ip_packet.id,
        'flags': ip_packet.flags,
        'off': ip_packet.off,
        'ttl': ip_packet.ttl,
        'p': ip_packet.p,
        'sum': ip_packet.sum,
        'src': ip_packet.src,
        'dst': ip_packet.dst,
        'opt': ip_packet.opt,
        'pad': ip_packet.pad,
        # 'payload': ip_packet.payload
    }


def get_pcap_time_limits(packets):
    timestamp_pcap_from = float('inf')
    timestamp_pcap_to = 0
    for pkt in packets:
        pkt_timestamp = pkt.timestamp + pkt.timestamp_ms / 1000000.
        if pkt_timestamp < timestamp_pcap_from:
            timestamp_pcap_from = pkt_timestamp
        if pkt_timestamp > timestamp_pcap_to:
            timestamp_pcap_to = pkt_timestamp
    return timestamp_pcap_from, timestamp_pcap_to


def parse_pcap(packets, csv=False):
    this = []
    field_names = ['timestamp', 'v', 'hl', 'tos', 'len', 'id', 'flags', 'off', 'ttl', 'p', 'sum', 'src', 'dst', 'opt', 'pad']
    if csv:
        csv_file = open('names.csv', 'w')
        writer = csv.DictWriter(csv_file, fieldnames=field_names)
        writer.writeheader()
    for pkt in packets:
        pkt_ts = pkt.timestamp + pkt.timestamp_ms / 1000000.
        if 1426436538.484 < pkt_ts < 1426437584.962:
            eth_frame = Ethernet(pkt.raw())
            ip_packet = IP(binascii.unhexlify(eth_frame.payload))
            pkt_obj = parse(ip_packet)
            pkt_obj['timestamp'] = pkt_ts
            this.append(pkt_obj)
            if csv:
                writer.writerow(pkt_obj)
    if csv:
        csv_file.close()
    return this

if __name__ == '__main__':
    if len(sys.argv) == 1:
        pcap_name = 'dump.pcap'
    else:
        pcap_name = sys.argv[1]

    pcap_file = open(pcap_name)

    pcap_data = savefile.load_savefile(pcap_file, verbose=True)

    parse_pcap(pcap_data.packets)