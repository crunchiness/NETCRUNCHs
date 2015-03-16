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
    stats_file.write('Response from cache: {0:.1f}%\n'.format(stats['from_cache'] * 100 / float(stats['total'])))
    stats_file.close()


def preprocess_json(data):
    """Filter out cache responses, build statistics"""
    pairs = data['pairs']
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
    for i, website in enumerate(pairs):
        stats['websites'][website] = 0
        for j, pair in enumerate(pairs[website]['pairs']):
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
    return {
        'pairs': filtered_data,
        'activeTab': data['activeTab'],
        'tabChanges': data['tabChanges']
    }


def preprocess_time_tab_data(json_data):
    active_tab = json_data['activeTab']
    tab_changes = json_data['tabChanges']
    opened_website = []
    for i in range(1, len(active_tab)):
        time_stamp_from = active_tab[i-1]['timeStamp']
        time_stamp_to = active_tab[i]['timeStamp']
        tab_id = active_tab[i-1]['tabId']
        website = None
        for change in tab_changes[tab_id]:
            if change['timeStamp'] <= time_stamp_from:
                website = change['website']
            elif change['timeStamp'] < time_stamp_to:
                if change['website'] != website:
                    opened_website.append({
                        'timeStamp': time_stamp_from,
                        'website': website
                    })
                    time_stamp_from = change['timeStamp']
                    website = change['website']
            else:
                opened_website.append({
                    'timeStamp': time_stamp_from,
                    'website': website
                })
                break
    return opened_website


def get_avg_delays(data):
    delays = {}
    for website in data:
        diff_sum = 0
        num_pairs = 0
        for pair in data[website]:
            diff_sum += pair['response']['timeStamp'] - pair['request']['timeStamp']
            num_pairs += 1
        avg_delay = diff_sum / (1000.0 * num_pairs)
        delays[website] = avg_delay
    return delays


def get_json_time_limits(data):
    first_request_time = float('inf')
    last_response_time = 0
    for website in data:
        for pair in data[website]:
            if pair['request']['timeStamp'] < first_request_time:
                first_request_time = pair['request']['timeStamp']
            if pair['response']['timeStamp'] > last_response_time:
                last_response_time = pair['response']['timeStamp']
    return TimeStamp(first_request_time / 1000.0), TimeStamp(last_response_time / 1000.0)

if __name__ == '__main__':
    if len(sys.argv) == 1:
        filename = 'data.json'
    else:
        filename = sys.argv[1]

    f = open(filename)
    data = json.load(f)
    preprocessed = preprocess_json(data)
    print get_avg_delays(preprocessed)
    a, b = get_json_time_limits(preprocessed)
    print 'from', a.get_datetime()
    print 'to', b.get_datetime()
    new_filename = filename[:-5] + '_preprocessed.json'
    f1 = open(new_filename, 'w')
    json.dump(preprocessed, f1)