import argparse
from pcapfile import savefile
from pcap_analyser import parse_pcap

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Converts PCAP to CSV.')
    parser.add_argument('pcap_name', nargs='?', type=str, help='input PCAP file (default \'dump.pcap\')',
                        default='dump.pcap')
    parser.add_argument('output', nargs='?', type=str, help='output file (default \'out.csv\')', default='out.csv')
    parser.add_argument('website', nargs='?', type=str, help='website/app to tag packets with')

    args = parser.parse_args()

    pcap_file = open(args.pcap_name)
    pcap_data = savefile.load_savefile(pcap_file, verbose=True)
    parse_pcap(pcap_data.packets, website=args.website, source='DIRECT', write_csv=True, csv_name=args.output)
