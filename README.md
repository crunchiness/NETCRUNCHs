usage: main.py [-h] [-p] [json_name] [pcap_name] [output]

NETCRUNCHs main module.

positional arguments:
  json_name           input JSON file ('data.json' or 'data_preprocessed.json'
                      by default)
  pcap_name           input PCAP file (default 'dump.pcap')
  output              output file (default 'out.csv')

optional arguments:
  -h, --help          show this help message and exit
  -p, --preprocessed  use preprocessed JSON

NETCRUNCHs also writes data, which can be used to identify problems into "stats.log".

Folder pcapfile contains python package "pypcapfile 0.8.2" (authors acknowledges in pcapfile/AUTHORS). Package has been modified as it was originally incapable of reading PCAP files produced by Tracedump.
