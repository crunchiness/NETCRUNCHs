import csv
import sys

stuff = {}

filename = sys.argv[1]
new_filename = filename[:-4] + '_small.csv'

csv_file = open(filename, 'rb')
csv_out = open(new_filename, 'w')
reader = csv.DictReader(csv_file)
writer = csv.DictWriter(csv_out, fieldnames=['website', 'packets'])
for row in reader:
    try:
        stuff[row['website']] += 1
    except KeyError:
        stuff[row['website']] = 1

for key in stuff:
    writer.writerow({'website': key, 'packets': stuff[key]})

csv_out.close()
csv_file.close()