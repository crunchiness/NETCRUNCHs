# -*- coding: utf-8 -*-
__author__ = 'crunch'
import json
import sys
from timestamp import TimeStamp

if len(sys.argv) == 1:
    filename = 'data.json'
else:
    filename = sys.argv[1]

f = open(filename)
data = json.load(f)
websites = {}
from_cache = 0
total = 0
only_response = 0
only_request = 0
both = 0
first_time_request = 1000000000000000000
first_time_response = 100000000000000000
last_time_response = 0
last_time_request = 0
wtf = {}

for i, website in enumerate(data):
    websites[website] = 0
    for j, pair in enumerate(data[website]['pairs']):
        if pair is None:
            wtf[website].append(j)
            continue
        if pair['response'] is not None and pair['request'] is None:
            only_response += 1
        if pair['request'] is not None and pair['response'] is None:
            only_request += 1
        if pair['request'] is None and pair['response'] is None:
            both += 1
        if pair['request'] is not None:
            if pair['request']['timeStamp'] > last_time_request:
                last_time_request = pair['request']['timeStamp']
            if pair['request']['timeStamp'] < first_time_request:
                first_time_request = pair['request']['timeStamp']
        if pair['response'] is not None:
            if pair['response']['fromCache']:
                from_cache += 1
            if pair['response']['timeStamp'] > last_time_response:
                last_time_response = pair['response']['timeStamp']
            if pair['response']['timeStamp'] < first_time_response:
                first_time_response = pair['response']['timeStamp']
        # print pair['request']['timeStamp'], pair['response']['timeStamp']
        websites[website] += 1
        total += 1
print 'wtf', wtf
print websites
print 'first_time_request', TimeStamp(first_time_response/1000.0).get_datetime()
print 'first_time_response', TimeStamp(first_time_response/1000.0).get_datetime()
print 'last_time_request', TimeStamp(last_time_request/1000.0).get_datetime()
print 'last_time_response', TimeStamp(last_time_response/1000.0).get_datetime()
print 'only response', only_response
print 'only request', only_request
print 'from cache', from_cache
print 'total', total
print 'percent from cache', from_cache / float(total)