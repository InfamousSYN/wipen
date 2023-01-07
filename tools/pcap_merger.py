#!/usr/bin/python3
from scapy.all import *
from argparse import *

class mergerClass():
    @classmethod
    def __init__(self, output_filename):
        self._PacketCount = 0
        self.output_filename = output_filename
        self._AllPackets = []

    @classmethod
    def update_PacketCount(self):
        self._PacketCount += 1

    @classmethod
    def get_PacketCount(self):
        return self._PacketCount

    @classmethod
    def write(self, packet=None):
        self.update_PacketCount()
        wrpcap(self.output_filename, packet, append=True)


if __name__ == '__main__':
    parser = ArgumentParser(prog=sys.argv[0],
        description='PCAP merging utility',
        usage='\r\nsudo python3 wipen/tools/pcap_merger.py -f pcaps/1.pcap pcaps/2.pcap -o output.pcap\r\nsudo python3 wipen/tools/pcap_merger.py -f pcaps/*.pcap -o output.pcap',
        add_help=True
    )

    parser.add_argument('-f', '--file',
        dest='pcap_filename',
        type=str,
        nargs='+',
        help='Provide one or more pcap to merge',
        required=True
    )

    parser.add_argument('-o', '--output',
        dest='output_filename',
        type=str,
        default=None,
        help='Specify output filename',
        required=True
    )

    # Basic error handling of the programs initalisation
    try:
        arg_test = sys.argv[1]
    except IndexError:
        parser.print_help()
        sys.exit

    args, leftovers = parser.parse_known_args()
    options = args.__dict__

    try:
        print('[+] Merging specified files:\r\n    {}'.format(options['pcap_filename']))
        merger = mergerClass(
            output_filename=options['output_filename'])
        allpackets = []
        for filename in options['pcap_filename']:
            print('[-] Reading file: {}'.format(filename))
            sniff(offline=filename, prn=merger.write, store=0)
        print('[-] Total packets written: {}'.format(merger.get_PacketCount()))
        print('[-] Merge completed')

    except Exception as e:
        print('[!] Error recieved:\r\n    {}'.format(e))
