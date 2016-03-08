import argparse
import csv
import binascii
from pcapfile import savefile
from pcapfile.protocols.network.ip import IP
from pcapfile.protocols.linklayer.ethernet import Ethernet
from pcap_analyser import parse, is_ack, get_ports, is_rst, is_fin

FIELD_NAMES = ['timestamp', 'v', 'hl', 'tos', 'len', 'id', 'flags', 'off', 'ttl', 'protocol', 'sum', 'src', 'dst',
               'opt', 'pad', 'website', 'source', 'is_ack', 'is_rst', 'is_fin', 'url', 'src_port', 'dst_port']


def parse_pcap(packets, csv_name='android_el_manana.csv'):
    shit = 0
    csv_file = open(csv_name, 'w')
    writer = csv.DictWriter(csv_file, fieldnames=FIELD_NAMES)
    writer.writeheader()
    for pkt in packets:
        pkt_ts = pkt.timestamp + pkt.timestamp_ms / 1000000.
        eth_frame = Ethernet(pkt.raw(), sll=False)
        try:
            ip_packet = IP(binascii.unhexlify(eth_frame.payload))
        except AssertionError:
            shit += 1
            continue
        pkt_obj = parse(ip_packet)
        pkt_obj['is_ack'] = is_ack(pkt_obj, ip_packet)
        pkt_obj['is_rst'] = is_rst(pkt_obj, ip_packet)
        pkt_obj['is_fin'] = is_fin(pkt_obj, ip_packet)
        pkt_obj['timestamp'] = pkt_ts
        pkt_obj['src_port'], pkt_obj['dst_port'] = get_ports(pkt_obj, ip_packet)
        pkt_obj['source'] = ''
        pkt_obj['website'] = 'youtube.com'
        if not (pkt_obj['src'] in ['127.0.0.1', '127.0.1.1'] or pkt_obj['dst'] in ['127.0.0.1', '127.0.1.1']):
            writer.writerow(pkt_obj)
    csv_file.close()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Converts PCAP to CSV.')
    parser.add_argument('pcap_name', nargs='?', type=str, help='input PCAP file (default \'dump.pcap\')',
                        default='dump.pcap')
    parser.add_argument('output', nargs='?', type=str, help='output file (default \'out.csv\')', default='out.csv')

    args = parser.parse_args()

    pcap_file = open(args.pcap_name)
    pcap_data = savefile.load_savefile(pcap_file, verbose=True)
    parse_pcap(pcap_data.packets, csv_name=args.output)
