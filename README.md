# wipen

`wipen` is an automated tool for interrogating 802.11 packets for target attribution; currently `wipen` supports two modes of operation:
- live interrogation: Performs channel hopping for user-defined period; during which will perform target attribution based on user-defined values. 
- pcap interrogation: Analyises an user-supplied PCAP file to perform target attribution based on user-defined values. During PCAP interrogation, `wipen` performs multiple parses of the PCAP to keep the overall memory usage low. 


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

**Note:** To target a SSID which contains a space within the name, place the value within single quotes ( `'` ) for the `-s` argument.


## Installation

```Bash
git clone https://github.com/InfamousSYN/wipen
python3 -m install -r wipen/requirements.txt
```


## Examples

### Live Interrogation

Using the `-m 0` argument, `wipen` can be placed into live capture mode. In live capture mode, `wipen` will automatically channel hop for a defined period (`-T`); during which it will perform analysis of captured packets for target attribution. 

```Bash
sudo python3 /opt/wipen/wipen.py -m 0 -i [INTERFACE] -o [OUTFILE] -s [TARGET SSID] --ssid-pattern [P1] [P2]  |tee -a [OUTFILE].log
```

**Note:** By default, while in live mode, `wipen` will not save the collected packets to a PCAP file. The user can invoke `wipen` to create a PCAP using the `--save-pcap` argument for data posterity. 

### PCAP Interrogation

Using the `-m 1` argument, `wipen` will interrogate a specified PCAP file of captured packets for target attribution. 

```Bash
sudo python3 /opt/wipen/wipen.py -f [PCAP CAP] --ssid-pattern [P1] [P2] -s [TARGET SSID] -o [OUTFILE] |tee -a [OUTFILE].log
```

**REQUIRED:** The input PCAP must have the `RadioTap` layer for `wipen` to determine the channel frequency and 802.11 data protocol used by the target SSID. This means, a cap file produced by [`airodump-ng`](https://www.aircrack-ng.org/doku.php?id=airodump-ng) used as the input will not display a frequency or protocol value for any of the BSSID. 

**Note:** When analysing a large PCAP file, it is recommended to use `tee` to pipe the STDOUT to a file for logging purposes. 


## Sample raw JSON schema

The result of the target attribution is to organise the interrogated information in an easily digestable JSON format to aid penetration testing activities and identifying information to report on. The JSON output builds following relationship: 
1. The target SSID is added to blank object
2. Any BSSID broadcasting target SSID are linked as list entries under the SSID
3. Any STA connected to a broadcasting BSSID are linked as list entries under the BSSID 
4. Any similar BSSID to linked BSSID are linked as list entries under the BSSID
5. Any probes request from linked STA are linked as list entries under the STA
6. Any EAPOL identity responses from linked STA are linked as list entries under the STA

The above schema is replicated for similar SSID (based on user-specified naming convention), with the similar SSID JSON structure being linked as list entries under the target SSID. 

The raw JSON object produced by `wipen` will be in the following schema:  

```
{
    "SSID1":{
        "bssid":[{
            "bssid":"a4:9b:cd:13:98:41",
            "frequency":149,
            "protocol":"802.11ac",
            "authentication":"WPA2/802.1X",
            "associated_clients":[{
                "client_addr":"5c:e9:1e:86:e1:73",
                "identities":[{
                    "identity":"bob",
                    "metadata":{
                        "_pid":"f9bdce2f-9bff-4f77-8cde-e34cf9388157",
                        "_id":"e154ed56-deb8-43e3-abf6-c60740c62135",
                        "_sid":[
                        ],
                        "_type":"identity"
                    }
                }],
                "probes":[{
                    "probe":"SSID2",
                    "metadata":{
                        "_pid":"f9bdce2f-9bff-4f77-8cde-e34cf9388157",
                        "_id":"e154ed56-deb8-43e3-abf6-c60740c62135",
                        "_sid":[
                        ],
                        "_type":"probe"
                    }
                }],
                "vendor":null,
                "metadata":{
                    "_pid":"bc1b58d1-4f26-41a4-a4ab-b879c692717b",
                    "_id":"f9bdce2f-9bff-4f77-8cde-e34cf9388157",
                    "_sid":[
                    ],
                    "_type":"sta"
                }
            }],
            "similar_bssid":[{
                "ssid":"SSID2",
                "bssid":"a4:9b:cd:13:98:40",
                "protocol":"802.11ac",
                "frequency":149,
                "authentication":"WPA2/PSK",
                "vendor":null,
                "times_seen":1,
                "hidden_ssid":false,
                "metadata":{
                    "_pid":null,
                    "_id":null,
                    "_sid":[
                    ],
                    "_type":"bssid"
                }
            }],
            "pmkid":null,
            "vendor":null,
            "wps":"wps",
            "times_seen":493,
            "hidden_ssid":false,
            "metadata":{
                "_pid":"76027153-2e7e-4b5f-8082-6893e943f3ee",
                "_id":"f094831c-5fa2-4b16-812a-4ec190c6cd33",
                "_sid":[
                ],
                "_type":"bssid"
            }
        }],
        "similar_ssid":[{
            "SSID2":{
                "bssid":[{
                    "bssid":"a4:9b:cd:13:98:40",
                    "frequency":149,
                    "protocol":"802.11ac",
                    "authentication":"WPA2/PSK",
                    "associated_clients":[{
                        "client_addr":"5c:e9:1e:86:e1:73",
                        "identities":[],
                        "probes":[{
                            "probe":"SSID2",
                            "metadata":{
                                "_pid":null,
                                "_id":"e154ed56-deb8-43e3-abf6-c60740c62135",
                                "_sid":[
                                ],
                                "_type":"probe"
                            }
                        }],
                        "vendor":null,
                        "metadata":{
                            "_pid":"bc1b58d1-4f26-41a4-a4ab-b879c692717b",
                            "_id":"f9bdce2f-9bff-4f77-8cde-e34cf9388157",
                            "_sid":[
                            ],
                            "_type":"sta"
                        }
                    }],
                    "similar_bssid":[],
                    "pmkid":null,
                    "vendor":null,
                    "wps":"wps",
                    "times_seen":512,
                    "hidden_ssid":false,
                    "metadata":{
                        "_pid":"9afc2c44-72e6-49cb-b18f-7db7aa3e8641",
                        "_id":"bc1b58d1-4f26-41a4-a4ab-b879c692717b",
                        "_sid":[
                        ],
                        "_type":"bssid"
                    }
                }
            ],
            "similar_ssid":[],
            "metadata":{
                "_pid":"76027153-2e7e-4b5f-8082-6893e943f3ee",
                "_id":"9afc2c44-72e6-49cb-b18f-7db7aa3e8641",
                "_sid":[
                ],
                "_type":null
            }
        }
    }],
        "metadata":{
            "_pid":null,
            "_id":"76027153-2e7e-4b5f-8082-6893e943f3ee",
            "_sid":[
            ],
            "_type":"ssid",
            "starttime":"2023-09-17 06:19:13.158616",
            "endtime":"2023-09-17 06:19:13.158616"
        }
    }
}
```

**Note:** The parent of an `identity` [dict](https://docs.python.org/3/tutorial/datastructures.html#dictionaries) is the `bssid` not the `sta`. 

### Sample JQ Queries

The [jq](https://github.com/jqlang/jq) utility can be used to parse the raw JSON object for interesting information. The above sample raw JSON object can be saved to a file and used to test the following queries. 


This query will extract a list of each probe, and then use the `sort` command to display only the unique probe requests.
```bash
jq -r '.. | if type == "object" and has("metadata") and .metadata._type == "probe" then .probe else empty end' test_struct.json |sort -u
```

This query will extract a list of each identity, and then use the `sort` command to display only the unique identities.
```bash
jq -r '.. | if type == "object" and has("metadata") and .metadata._type == "identity" then .identity else empty end' test/test_struct.json |sort -u
```


## Additional tools
There are addition tools that can support `wipen`, or leverage the produced JSON object. For more information, refer to the tool's [README](https://github.com/InfamousSYN/wipen/blob/main/tools/README.md) documentation.

## Roadmap
  - Populate WPS status
  - Improve processing workflow, by having target and similar searchs performed co-currently. With 3 reads of the PCAP file (currently there are 7 reads). 
    - Read 2
      - Merge target and similar client search
      - Merge target and similar BSSID search
    - Read 3
      - Merge target and similar probe search
      - Merge target and similar identity search
      - Merge target and similar PMKID search
      - Merge target and similar WPS search

