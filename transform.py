import csv
stuff = {}
with open('one-maximize.csv', 'rb') as csvfile:
    spamreader = csv.reader(csvfile)
    for row in spamreader:
        try:
            stuff[row[1]][row[0]] = row[2]
        except KeyError:
            stuff[row[1]] = {row[0]: row[2]}

with open('eggs.csv', 'wb') as csvfile:
    spamwriter = csv.writer(csvfile)
    spamwriter.writerow(['Delay', 'Tumblr', 'Facebook'])
    for key in stuff:
        spamwriter.writerow([key, stuff[key]['tumblr.com'], stuff[key]['facebook.com']])
