#!/usr/bin/env python
__author__ = 'Ingvaras Merkys'

import binascii
import csv
import argparse
from pcapfile import savefile
from pcapfile.protocols.network.ip import IP
from pcapfile.protocols.linklayer.ethernet import Ethernet
from timestamp import TimeStamp

# field names of output file
FIELD_NAMES = ['timestamp', 'v', 'hl', 'tos', 'len', 'id', 'flags', 'off', 'ttl', 'p', 'sum', 'src', 'dst', 'opt',
               'pad', 'website', 'source']


def parse(ip_packet):
    """Parses IP packet"""
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
    """"Gets accurate time limits of PCAP data"""
    timestamp_pcap_from = float('inf')
    timestamp_pcap_to = 0
    for pkt in packets:
        pkt_timestamp = pkt.timestamp + pkt.timestamp_ms / 1000000.
        if pkt_timestamp < timestamp_pcap_from:
            timestamp_pcap_from = pkt_timestamp
        if pkt_timestamp > timestamp_pcap_to:
            timestamp_pcap_to = pkt_timestamp
    return timestamp_pcap_from, timestamp_pcap_to


def parse_pcap(packets, timestamp_abs_from, timestamp_abs_to, write_csv=False, csv_name='dump.csv'):
    """Produces python list from pcap file"""
    pcap_list = []
    writer = None
    csv_file = None
    if write_csv:
        csv_file = open(csv_name, 'w')
        writer = csv.DictWriter(csv_file, fieldnames=FIELD_NAMES)
        writer.writeheader()
    for pkt in packets:
        pkt_ts = pkt.timestamp + pkt.timestamp_ms / 1000000.
        if timestamp_abs_from.get_seconds() < pkt_ts < timestamp_abs_to.get_seconds():
            eth_frame = Ethernet(pkt.raw(), sll=True)
            ip_packet = IP(binascii.unhexlify(eth_frame.payload))
            pkt_obj = parse(ip_packet)
            pkt_obj['timestamp'] = pkt_ts
            pkt_obj['source'] = set([])
            pkt_obj['website'] = set([])
            if not (pkt_obj['src'] in ['127.0.0.1', '127.0.1.1'] or pkt_obj['dst'] in ['127.0.0.1', '127.0.1.1']):
                pcap_list.append(pkt_obj)
                if write_csv:
                    writer.writerow(pkt_obj)
    if write_csv:
        csv_file.close()
    return pcap_list


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Produces CSV from PCAP file.')
    parser.add_argument('pcap_name', nargs='?', type=str, help='input PCAP file (\'dump.pcap\' by default)',
                        default='dump.pcap')
    args = parser.parse_args()
    file_name = args.pcap_name
    out_name = file_name[:-5] + '.csv'
    pcap_file = open(file_name)
    pcap_data = savefile.load_savefile(pcap_file, verbose=True)
    time_from, time_to = get_pcap_time_limits(pcap_data.packets)
    parse_pcap(pcap_data.packets, TimeStamp(time_from), TimeStamp(time_to), write_csv=True, csv_name=out_name)
    pcap_file.close()
