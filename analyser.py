# -*- coding: utf-8 -*-
__author__ = 'crunch'
import json
import sys
import time
from timestamp import TimeStamp


def write_stats(stats):
    # stats = {
    #     'websites': {},
    #     'from_cache': 0,
    #     'total': 0,
    #     'response_only': 0,
    #     'request_only': 0,
    #     'no_data': 0,
    #     'wtf': {}
    # }
    stats_file = open('stats.log', 'a')
    stats_file.write('='*100 + '\n')
    stats_file.write(time.strftime("%c") + '\n')
    stats_file.write('='*100 + '\n')
    stats_file.write(str(stats['websites']) + '\n')
    stats_file.write('# of pairs (incl. empty): {0}\n'.format(stats['total']))
    stats_file.write('# of empty pairs: {0}\n'.format(stats['no_data']))
    stats_file.write('# of pairs with request only: {0}\n'.format(stats['request_only']))
    stats_file.write('# of pairs with response only: {0}\n'.format(stats['response_only']))
    stats_file.write('# of responses from disk cache: {0}\n'.format(stats['from_cache']))
    stats_file.write('Response from cache: {0:.1f}\n'.format(stats['from_cache'] * 100 / float(stats['total'])))
    stats_file.close()


def preprocess_json(data):
    """Filter out cache responses, build statistics"""
    stats = {
        'websites': {},
        'from_cache': 0,
        'total': 0,
        'response_only': 0,
        'request_only': 0,
        'no_data': 0,
        # 'first_request_time': float('inf'),
        # 'first_response_time': float('inf'),
        # 'last_request_time': 0,
        # 'last_response_time': 0,
        'wtf': {}
    }
    filtered_data = {}
    for i, website in enumerate(data):
        stats['websites'][website] = 0
        for j, pair in enumerate(data[website]['pairs']):
            if pair is None:
                stats['no_data'] += 1
                try:
                    stats['wtf'][website].append(j)
                except KeyError:
                    stats['wtf'][website] = [j]
            elif pair['response'] is None and pair['request'] is None:
                stats['no_data'] += 1
            elif pair['response'] is None:
                stats['request_only'] += 1
            elif pair['request'] is None:
                stats['response_only'] += 1
            else:
                if pair['response']['fromCache']:
                    stats['from_cache'] += 1
                else:
                    try:
                        filtered_data[website].append(pair)
                    except KeyError:
                        filtered_data[website] = [pair]
            stats['websites'][website] += 1
            stats['total'] += 1
    write_stats(stats)
    return filtered_data


if len(sys.argv) == 1:
    filename = 'data.json'
else:
    filename = sys.argv[1]

f = open(filename)
data = json.load(f)
preprocessed = preprocess_json(data)
new_filename = filename[:-5] + '_preprocessed.json'
f1 = open(new_filename, 'w')
json.dump(preprocessed, f1)

# print 'first_time_request', TimeStamp(first_time_response / 1000.0).get_datetime()
# print 'first_time_response', TimeStamp(first_time_response / 1000.0).get_datetime()
# print 'last_time_request', TimeStamp(last_time_request / 1000.0).get_datetime()
# print 'last_time_response', TimeStamp(last_time_response / 1000.0).get_datetime()
