#!/usr/bin/python3
from pathlib import Path
import json
import uuid

def deep_search(target_key=None, payload=None):
    import json
    payload=json.dumps(payload)
    results = []
    def _decode_dict(a_dict):
        try:
            results.append(a_dict[target_key])
        except KeyError:
            pass
        return a_dict
    json.loads(payload, object_hook=_decode_dict)
    return results


def populateNodes(data=None, filename=None):
    import uuid
    data_set = {"nodes":[],"edges":[]}

    bssid_ssid='Broadcasting'
    sta_ssid='ProbingFor'
    ssid_ssid='SimilarSSID'
    sta_identity='ActingAs'
    identity_bssid_psk='ConnectedToViaPSK'
    identity_bssid_eap='ConnectedToViaEAP'
    bssid_bssid='SimilarBSSID'

    unknown_identity_count = 1

    # add the initial target ssid node
    for _ssid_pos, _ssid in enumerate(data):
        payload=data[_ssid]
        data_set["nodes"].append({"label":_ssid, "wipen_type":payload['metadata'].get('_type'), "uuid":payload['metadata'].get('_id')})

        for _similar_ssid_pos, _similar_ssid in enumerate(data[_ssid]['similar_ssid']):
            _similar_ssid=next(iter(_similar_ssid))
            payload = data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]
            data_set["nodes"].append({"label":_similar_ssid, "wipen_type":payload['metadata'].get('_type'), "uuid":payload['metadata'].get('_id')})
            data_set["edges"].append({"label":ssid_ssid, "source":payload['metadata'].get('_id'), "destination":data[_ssid]['metadata'].get('_id')})

        for _bssid_pos, _bssid in enumerate(data[_ssid]['bssid']):
            payload = data[_ssid]['bssid'][_bssid_pos]
            data_set["nodes"].append({"label":payload.get('bssid'), "wipen_type":payload['metadata'].get('_type'), "uuid":payload['metadata'].get('_id'), 'frequency':payload.get('frequency'), 'protocol':payload.get('protocol'), 'authentication':payload.get('authentication'), 'pmkid':payload.get('pmkid'), 'vendor':payload.get('vendor'), 'wps':payload.get('wps'), 'times_seen':payload.get('times_seen')})
            data_set["edges"].append({"label":bssid_ssid, "source":payload['metadata'].get('_id'), "destination":data[_ssid]['metadata'].get('_id')})

        for _similar_ssid_pos, _similar_ssid in enumerate(data[_ssid]['similar_ssid']):
            _similar_ssid=next(iter(_similar_ssid))
            for _similar_ssid_bssid_pos, _similar_ssid_bssid in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid']):
                payload = data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]
                data_set["nodes"].append({"label":payload.get('bssid'), "wipen_type":payload['metadata'].get('_type'), "uuid":payload['metadata'].get('_id'), 'frequency':payload.get('frequency'), 'protocol':payload.get('protocol'), 'authentication':payload.get('authentication'), 'pmkid':payload.get('pmkid'), 'vendor':payload.get('vendor'), 'wps':payload.get('wps'), 'times_seen':payload.get('times_seen')})
                data_set["edges"].append({"label":bssid_ssid, "source":payload['metadata'].get('_id'), "destination":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['metadata'].get('_id')})

    # add the client
    for _ssid_pos, _ssid in enumerate(data):
        for _bssid_pos, _bssid in enumerate(data[_ssid]['bssid']):

            ########################################################
            # Create a PSK for target BSSID                        #
            # Creates a STA node and a corrosponding identity node #
            ########################################################
            if('PSK'.lower() in data[_ssid]['bssid'][_bssid_pos].get('authentication').lower()
            ):
                for _client_pos, _client in enumerate(data[_ssid]['bssid'][_bssid_pos]['associated_clients']):

                    payload = data[_ssid]['bssid'][_client_pos]['associated_clients'][_client_pos]
                    if( (payload.get('client_addr') not in deep_search(
                        target_key='label',
                        payload=data_set['nodes']
                    ))):
                        data_set["nodes"].append({"label":payload.get("client_addr"), "vendor":payload.get("vendor"), "wipen_type":payload['metadata'].get('_type'), "uuid":payload["metadata"].get("_id")})

                    target_key = {"label":payload.get("client_addr"), "wipen_type":"sta"}

                    if(any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                        _uuid = next((d for d in data_set["nodes"] if all(d[k] == v for k, v in target_key.items())))
                        _uuid = _uuid.get("uuid")
                    else:
                        _uuid = str(uuid.uuid4())
                        data_set["nodes"].append({"label":payload.get("client_addr"), "wipen_type":"identity", "uuid":_uuid})

                    data_set["edges"].append({"label":sta_identity, "source":payload['metadata'].get('_id'), "destination":_uuid})
                    data_set["edges"].append({"label":identity_bssid_psk, "source":_uuid, "destination":data[_ssid]['bssid'][_bssid_pos]['metadata'].get('_id')})

                    payload = data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]
                    target_key = {"label":payload.get("identity"), "wipen_type":payload['metadata'].get('_type')}
                    if(any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                        _uuid = next((d for d in data_set["nodes"] if all(d[k] == v for k, v in target_key.items())))
                        _uuid = _uuid.get("uuid")
                    else:
                        _uuid = str(uuid.uuid4())
                        data_set["nodes"].append({"label":payload.get("client_addr"), "wipen_type":"identity", "uuid":_uuid})

                    data_set["edges"].append({"label":sta_identity, "source":payload['metadata'].get('_id'), "destination":_uuid})
                    data_set["edges"].append({"label":identity_bssid_psk, "source":_uuid, "destination":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['metadata'].get('_id')})


            ########################################################
            # Create a 802.1x for target SSID                      #
            # Creates a STA node and a corrosponding identity node #
            ########################################################
            if('802.1X'.lower() in data[_ssid]['bssid'][_bssid_pos].get('authentication').lower() ):
                for _client_pos, _client in enumerate(data[_ssid]['bssid'][_bssid_pos]['associated_clients']):

                    payload = data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]
                    target_key = {"label":payload.get("client_addr"), "wipen_type":"sta"}
                    if(not any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                        data_set["nodes"].append({"label":payload.get("client_addr"), "vendor":payload.get("vendor"), "wipen_type":payload['metadata'].get('_type'), "uuid":payload["metadata"].get("_id")})
                    else: pass

                    if( len(_client.get('identities')) >= 1 ):
                        for _identity_pos, _identity in enumerate(data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]['identities']):
                        
                            payload = data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]['identities'][_identity_pos]
                            target_key = {"label":payload.get("identity"), "wipen_type":payload['metadata'].get('_type')}
                            if(not any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                                data_set["nodes"].append({"label":payload.get("identity"), "wipen_type":payload['metadata'].get('_type'), "uuid":payload["metadata"].get("_id")})

                            target_key = {"label":sta_identity, "source":data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]['metadata'].get('_id'), "destination":payload["metadata"].get("_id")}
                            if(not any(d for d in data_set["edges"] if sum(d.get(k) == v for k, v in target_key.items()) >= 3)):
                                data_set["edges"].append({"label":sta_identity, "source":data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]['metadata'].get('_id'), "destination":payload["metadata"].get("_id")})
                            else: pass

                            target_key = {"label":identity_bssid_eap, "source":payload["metadata"].get("_id"), "destination":data[_ssid]['bssid'][_bssid_pos]['metadata'].get('_id')}
                            if(not any(d for d in data_set["edges"] if sum(d.get(k) == v for k, v in target_key.items()) >= 3)):
                                data_set["edges"].append({"label":identity_bssid_eap, "source":payload["metadata"].get("_id"), "destination":data[_ssid]['bssid'][_bssid_pos]['metadata'].get('_id')})
                            else: pass
                    elif( len(_client.get('identities')) == 0 ):
                        # make a dummy identity when unknown
                        _uuid = str(uuid.uuid4())
                        data_set["nodes"].append({"label":"unknown_identity_{}".format(unknown_identity_count), "wipen_type":"identity", "uuid":_uuid})
                        unknown_identity_count += 1
                        data_set["edges"].append({"label":sta_identity, "source":data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]['metadata'].get('_id'), "destination":_uuid})
                        data_set["edges"].append({"label":identity_bssid_eap, "source":_uuid, "destination":data[_ssid]['bssid'][_bssid_pos]['metadata'].get('_id')})

                    else:pass

            else: pass

        for _similar_ssid_pos, _similar_ssid in enumerate(data[_ssid]['similar_ssid']):
            _similar_ssid=next(iter(_similar_ssid))
            for _similar_ssid_bssid_pos, _similar_ssid_bssid in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid']):

                ########################################################
                # Create a PSK for similar ssid                        #
                # Creates a STA node and a corrosponding identity node #
                ########################################################
                if('PSK'.lower() in data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos].get('authentication').lower()
                ):
                    for _client_pos, _client in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients']):

                        payload = data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]
                        if( (data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos].get('client_addr') not in deep_search(
                            target_key='label',
                            payload=data_set['nodes']
                        )) ):
                            data_set["nodes"].append({"label":payload.get("client_addr"), "vendor":payload.get("vendor"), "wipen_type":payload['metadata'].get('_type'), "uuid":payload["metadata"].get("_id")})

                        target_key = {"label":payload.get("client_addr"), "wipen_type":"identity"}
                        if(any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                            _uuid = next((d for d in data_set["nodes"] if all(d[k] == v for k, v in target_key.items())))
                            _uuid = _uuid.get("uuid")
                        else:
                            _uuid = str(uuid.uuid4())
                            data_set["nodes"].append({"label":payload.get("client_addr"), "wipen_type":"identity", "uuid":_uuid})

                        data_set["edges"].append({"label":sta_identity, "source":payload['metadata'].get('_id'), "destination":_uuid})
                        data_set["edges"].append({"label":identity_bssid_psk, "source":_uuid, "destination":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['metadata'].get('_id')})


                ########################################################
                # Create a 802.1x for similar ssid                     #
                # Creates a STA node and a corrosponding identity node #
                ########################################################
                if('802.1X'.lower() in data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos].get('authentication').lower() ):
                    for _client_pos, _client in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients']):
    
                        payload = data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]
                        target_key = {"label":payload.get("client_addr"), "wipen_type":"sta"}
                        if(not any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                            data_set["nodes"].append({"label":payload.get("client_addr"), "vendor":payload.get("vendor"), "wipen_type":payload['metadata'].get('_type'), "uuid":payload["metadata"].get("_id")})

                        if( len(_client.get('identities')) >= 1 ):
                            for _identity_pos, _identity in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]['identities']):

                                payload = data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]['identities'][_identity_pos]
                                target_key = {"label":payload.get("identity"), "wipen_type":payload['metadata'].get('_type')}
                                if(not any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 2)):
                                    data_set["nodes"].append({"label":payload.get("identity"), "wipen_type":payload['metadata'].get('_type'), "uuid":payload["metadata"].get("_id")})

                                target_key = {"label":sta_identity, "source":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]['metadata'].get('_id'), "destination":payload["metadata"].get("_id")}
                                if(not any(d for d in data_set["edges"] if sum(d.get(k) == v for k, v in target_key.items()) >= 3)):
                                    data_set["edges"].append({"label":sta_identity, "source":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]['metadata'].get('_id'), "destination":payload["metadata"].get("_id")})
                                else: pass

                                target_key = {"label":identity_bssid_eap, "source":payload["metadata"].get("_id"), "destination":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['metadata'].get('_id')}
                                if(not any(d for d in data_set["edges"] if sum(d.get(k) == v for k, v in target_key.items()) >= 3)):
                                    data_set["edges"].append({"label":identity_bssid_eap, "source":payload["metadata"].get("_id"), "destination":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['metadata'].get('_id')})
                                else: pass

                        elif(len(_client.get('identities')) == 0):
                            # make a dummy identity when unknown
                            _uuid = str(uuid.uuid4())
                            data_set["nodes"].append({"label":"unknown_identity_{}".format(unknown_identity_count), "wipen_type":"identity", "uuid":_uuid})
                            unknown_identity_count += 1
                            data_set["edges"].append({"label":sta_identity, "source":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]['metadata'].get('_id'), "destination":_uuid})
                            data_set["edges"].append({"label":identity_bssid_eap, "source":_uuid, "destination":data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['metadata'].get('_id')})
                        else: pass

    # add the probe
    for _ssid_pos, _ssid in enumerate(data):
        for _bssid_pos, _bssid in enumerate(data[_ssid]['bssid']):
            for _client_pos, _client in enumerate(data[_ssid]['bssid'][_bssid_pos]['associated_clients']):
                client_payload = data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]
                for _probe_pos, _probe in enumerate(data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]['probes']):

                    payload = data[_ssid]['bssid'][_bssid_pos]['associated_clients'][_client_pos]['probes'][_probe_pos]

                    # check if ssid node for probe already exists
                    # then add edge between sta and ssid 
                    # else create a new ssid node for probe, 
                    # then add edge between sta and ssid 
                    target_key = {"label":payload.get('probe')}
                    if( any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 1) ):
                        parentSSID = next((d for d in data_set["nodes"] if all(d[k] == v for k, v in target_key.items())))
                        data_set["edges"].append({"label":sta_ssid, "source":client_payload['metadata'].get('_id'), "destination":parentSSID.get('uuid')})
                    else:
                        _uuid = str(uuid.uuid4())
                        data_set["nodes"].append({"label":payload.get('probe'), "wipen_type":"ssid", "uuid":_uuid})
                        data_set["edges"].append({"label":sta_ssid, "source":client_payload['metadata'].get('_id'), "destination":_uuid})

        for _similar_ssid_pos, _similar_ssid in enumerate(data[_ssid]['similar_ssid']):
            _similar_ssid=next(iter(_similar_ssid))
            for _similar_ssid_bssid_pos, _similar_ssid_bssid in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid']):
                for _client_pos, _client in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients']):
                    client_payload = data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]
                    for _probe_pos, _probe in enumerate(data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]['probes']):

                        payload = data[_ssid]['similar_ssid'][_similar_ssid_pos][_similar_ssid]['bssid'][_similar_ssid_bssid_pos]['associated_clients'][_client_pos]['probes'][_probe_pos]
                        target_key = {"label":payload.get('probe')}
                        if( any(d for d in data_set["nodes"] if sum(d.get(k) == v for k, v in target_key.items()) >= 1) ):
                            parentSSID = next((d for d in data_set["nodes"] if all(d[k] == v for k, v in target_key.items())))
                            data_set["edges"].append({"label":sta_ssid, "source":client_payload['metadata'].get('_id'), "destination":parentSSID.get('uuid')})
                        else:
                            _uuid = str(uuid.uuid4())
                            data_set["nodes"].append({"label":payload.get('probe'), "wipen_type":"ssid", "uuid":_uuid})
                            data_set["edges"].append({"label":sta_ssid, "source":client_payload['metadata'].get('_id'), "destination":_uuid})

    output_filename = "{}.wipen-ui.json".format(Path(filename).stem)
    with open('{}'.format(output_filename), 'w') as f:
        f.write(json.dumps(data_set))
    #print((data_set))


if __name__ == '__main__':
    import argparse
    import sys
    import json
    parser = argparse.ArgumentParser(prog=sys.argv[0],
            description='automated wireless pcap dissector',
            usage='sudo python3 wipen_to_wipen-ui.py -f [JSON]',
            add_help=True
    )

    parser.add_argument('-f', '--file',
        dest='json_filename',
        type=str,
        help='Provide one json to analysis',
    )

    # Basic error handling of the programs initalisation
    try:
        arg_test = sys.argv[1]
    except IndexError:
        parser.print_help()
        sys.exit(1)

    args, leftovers = parser.parse_known_args()

    with open(args.__dict__['json_filename']) as data_file:
        data = json.loads(data_file.read())

    result = populateNodes(data=data, filename=args.__dict__['json_filename'])
    

