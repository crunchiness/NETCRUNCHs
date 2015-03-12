# -*- coding: utf-8 -*-
__author__ = 'crunch'
import json
import argparse
from pcapfile import savefile
from json_analyser import get_json_time_limits, preprocess_json
from pcap_analyser import get_pcap_time_limits
from timestamp import TimeStamp


def get_abs_time_limits(ts1_from, ts1_to, ts2_from, ts2_to):
    """Finds overlap between two time intervals"""
    if ts1_from > ts2_from:
        t_min_from = ts1_from
    else:
        t_min_from = ts2_from
    if ts1_to < ts2_to:
        t_min_to = ts1_to
    else:
        t_min_to = ts2_to
    return t_min_from, t_min_to


def main(json_name, pcap_name, preprocessed):
    """Main method"""
    json_file = open(json_name)
    pcap_file = open(pcap_name)
    if preprocessed:
        json_data = json.load(json_file)
    else:
        raw_json_data = json.load(json_file)
        json_data = preprocess_json(raw_json_data)
    pcap_data = savefile.load_savefile(pcap_file, verbose=True)
    timestamp_json_from, timestamp_json_to = get_json_time_limits(json_data)
    timestamp_pcap_from, timestamp_pcap_to = get_pcap_time_limits(pcap_data.packets)
    timestamp_abs_from, timestamp_abs_to = get_abs_time_limits(timestamp_json_from, timestamp_json_to,
                                                               TimeStamp(timestamp_pcap_from),
                                                               TimeStamp(timestamp_pcap_to))
    print 'timestamp_abs_from', timestamp_abs_from.get_datetime()
    print 'timestamp_abs_to', timestamp_abs_to.get_datetime()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Description.')
    parser.add_argument('-p', '--preprocessed', help='use preprocessed JSON',
                        action='store_true')
    parser.add_argument('json_name', nargs='?', type=str, help='input JSON file')
    parser.add_argument('pcap_name', nargs='?', type=str, help='input PCAP file', default='dump.pcap')

    args = parser.parse_args()

    if args.json_name is None:
        if args.preprocessed:
            args.json_name = 'data_preprocessed.json'
        else:
            args.json_name = 'data.json'

    main(args.json_name, args.pcap_name, args.preprocessed)