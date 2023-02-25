# wipen

`wipen` is an automated tool for interrogating 802.11 packets for target attribution; currently `wipen` supports two modes of operation:
- live interrogation: Performs channel hopping for user-defined period; during which will perform target attribution based on user-defined values. 
- pcap interrogation: Analyises an user-supplied PCAP file to perform target attribution based on user-defined values. During PCAP interrogation, `wipen` performs multiple parses of the PCAP to keep the overall memory usage low. 

The result of the target attribution is to organise the interrogated information in an easily digestable JSON format to aid penetration testing activities and identifying information to report on. The JSON output builds following relationship: 
1. performs a search for BSSID broadcasting target SSID
2. performs a search for similar BSSID to known BSSID broadcasting target SSID
3. performs a search for similar SSID pattern to target SSID and populate BSSID broadcasting the similar SSID
4. Search for interesting metadata for parent level SSID and for each identified similar SSID per parent level SSID.
 - Map connected STA to known BSSID
  - identify all SSID probed for by connected STA
  - identify all EAP identities sent by connected STA
 - Populate PMKID information for known BSSID ( ON ROADMAP )
 - Populate WPS status ( ON ROADMAP )


## Installation

```Bash
git clone https://github.com/InfamousSYN/wipen
python3 -m install -r wipen/requirements.txt
```

## Usage

```Bash
usage: sudo python3 /opt/wipen/wipen.py -f [PCAP CAP] --ssid-pattern [P1] [P2] -s [TARGET SSID] -o [OUTFILE] |tee -a [OUTFILE].log

automated wireless pcap dissector

options:
  -h, --help            show this help message and exit

General Settings:
  -v, --verbose         Enable verbose
  --show-final          Show final JSON payload
  -o OUTPUT_FILENAME, --output OUTPUT_FILENAME
                        Specify output filename
  --threshold PERIODIC_FILE_UPDATE
                        Set periodic update for output file time in minutes (default: 15)

Packet Source Settings:
  Specify source for targeting information

  -m {0,1}              0 = live, 1 = pcap

Live Parsing Settings:
  Specify packet location when `-m 0` has been selected

  -i INTERFACE, --interface INTERFACE
                        Specify the wireless interface to use to capture packets
  -r HOP_RATE, --rate HOP_RATE
                        Control how quickly interface will hop to next channel in seconds (Default: 1 second)
  -T CAPTURE_LENGTH, --timer CAPTURE_LENGTH
                        Specify how long to capture packets for (Default: 30 second)
  --save-pcap           Create pcap of captured packets instead of discarding packets
  -O OUTPUT_PCAP, --output-pcap OUTPUT_PCAP
                        Specify name of pcap to store live captured packets

PCAP Parsing Settings:
  Specify packet location when `-m 1` has been selected

  -f PCAP_FILENAME [PCAP_FILENAME ...], --file PCAP_FILENAME [PCAP_FILENAME ...]
                        Provide one or more pcap to analysis

Packet Processing Settings:
  Control the level of interrogation that is performed per packet

  --skip-similar-bssid  Skip searching for similar BSSID
  --skip-similar-ssid   Skip searching for similar SSID
  -s TARGET_SSID [TARGET_SSID ...], --ssid TARGET_SSID [TARGET_SSID ...]
                        Specify a one ore more SSID to analysis
  --ssid-pattern SSID_PATTERN [SSID_PATTERN ...]
                        Provide one or more possible SSID patterns to search for.
  -I IGNORE_BSSID [IGNORE_BSSID ...], --ignore-bssid IGNORE_BSSID [IGNORE_BSSID ...]
                        Specify one or more BSSID to ignore during the parsing (default: ['00:11:22:33:44:55',
                        'ff:ff:ff:ff:ff:ff'])
  --ignore-client IGNORE_CLIENT [IGNORE_CLIENT ...]
                        Specify one or more STA addresses to ignore during parsing (default:
                        ['00:11:22:33:44:00'])
  --depth DEPTH         Depth to match the number of fields of a BSSID address (default: 5)
  --disable-vendor-mac-refresh
                        Disable refresh of vendor MAC table refresh (default: False)

```


### Output JSON Object Schema

The JSON object produced by `wipen` will be in the following schema:  

```
{
  "ssid":{
      "bssid":[{
              "bssid":str,
              "frequency":int,
              "protocol":str,
              "authentication":str,
              "associated_clients":[{
                'client_addr':str,
                'identities':[{
                  'id':int,
                  'identity':str
                }],
                'probes':[{
                  'id':int,
                  'probe':str
                }],
                'vendor':str
              }],
              "similar_bssid":[{
                "ssid":str,
                "bssid":str,
                "protocol":str,
                "frequency":int,
                "authentication":str,
                "vendor":str,
                "times_seen":int,
                "hidden_ssid":boolean,
              }],
              "pmkid":[],
              "vendor":str,
              "wps":str,
              "times_seen":int,
              "hidden_ssid":boolean
          }],
      "similar_ssid":[{
        "ssid":{
            "bssid":[{
                    "bssid":str,
                    "frequency":int,
                    "protocol":str,
                    "authentication":str,
                    "associated_clients":[{
                      'client_addr':str,
                      'identities':[{
                        'id':int,
                        'identity':str,
                        'bssid':str
                      }],
                      'probes':[{
                        'id':int,
                        'probe':str
                      }],
                      'vendor':str
                    }],
                    "similar_bssid":[{
                      "ssid":str,
                      "bssid":str,
                      "protocol":str,
                      "frequency":int,
                      "authentication":str,
                      "vendor":str,
                      "times_seen":int,
                      "hidden_ssid":boolean,
                    }],
                    "pmkid":[],
                    "vendor":str,
                    "wps":str,
                    "times_seen":int,
                    "hidden_ssid":boolean
                }],
            "similar_ssid":[]
        }
    }]
  }
}
```

**Note:** To target a SSID which contains a space within the name, place the value within single quotes ( `'` ) for the `-s` argument.


### Examples

#### Live Interrogation

Using the `-m 0` argument, `wipen` can be placed into live capture mode. In live capture mode, `wipen` will automatically channel hop for a defined period (`-T`); during which it will perform analysis of captured packets for target attribution. 

```Bash
sudo python3 /opt/wipen/wipen.py -m 0 -i [INTERFACE] -o [OUTFILE] -s [TARGET SSID] --ssid-pattern [P1] [P2]  |tee -a [OUTFILE].log
```

**Note:** By default, while in live mode, `wipen` will not save the collected packets to a PCAP file. The user can invoke `wipen` to create a PCAP using the `--save-pcap` argument for data posterity. 

#### PCAP Interrogation

Using the `-m 1` argument, `wipen` will interrogate a specified PCAP file of captured packets for target attribution. 

```Bash
sudo python3 /opt/wipen/wipen.py -f [PCAP CAP] --ssid-pattern [P1] [P2] -s [TARGET SSID] -o [OUTFILE] |tee -a [OUTFILE].log
```

**REQUIRED:** The input PCAP must have the `RadioTap` layer for `wipen` to determine the channel frequency and 802.11 data protocol used by the target SSID. This means, a cap file produced by [`airodump-ng`](https://www.aircrack-ng.org/doku.php?id=airodump-ng) used as the input will not display a frequency or protocol value for any of the BSSID. 

**Note:** When analysing a large PCAP file, it is recommended to use `tee` to pipe the STDOUT to a file for logging purposes. 

### Additional tools
There are addition tools that can support `wipen`, or leverage the produced JSON object. For more information, refer to the tool's [README](https://github.com/InfamousSYN/wipen/blob/main/tools/README.md) documentation.


## To Do
- Add a task queue system that watches for new content in the json object and then uses workers to perform action. IE When a new BSSID for the parent is added, a worker then opens the PCAP and iterates over the packet collection to count the total number of time the BSSID was seen and begins to search for connected clients and other similar BSSID. The number of parallel subtasks being ran at a time is controllable through argparse with a default of 2. 
- look at finding similar ssid based on [`difflib`](https://docs.python.org/2/library/difflib.html)
- detect WEP rather than listing as WPA/PSK
