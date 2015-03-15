import csv

stuff = {}

with open('one-res-maxim.txt', 'rb') as csv_file:
    csv_reader = csv.reader(csv_file)
    for row in csv_reader:
        try:
            stuff[row[1]][row[0]] = row[2]
        except KeyError:
            stuff[row[1]] = {row[0]: row[2]}

with open('one-res-max-compact.csv', 'wb') as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(['Delay', 'Tumblr', 'Facebook'])
    for key in stuff:
        csv_writer.writerow([key, stuff[key]['tumblr.com'], stuff[key]['facebook.com']])
