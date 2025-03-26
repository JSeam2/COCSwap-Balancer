import uuid
import json
from eth_abi import encode
import requests
import secrets
import time
import traceback
from web3 import Web3
import os

LATEST_UUID = str(uuid.uuid4())
ARTIFACT_NAME="balancer_fee_model"
USER_ID="8c9f812f-b85e-47d6-9fca-c4f9b34622b7"
DEPLOYMENT_NAME="0195d1ec-e714-72e4-baef-578131cc7f39"

DEBUG = False

# Open input.json
path = os.path.dirname(os.path.realpath(__file__))

with open(os.path.join(path, 'input.json')) as f:
    data = json.load(f)

# format input.json to suitable form
data["output_data"] = None
data["input_data"] = [data["input_data"]]

if DEBUG:
    print(data)

try:
    res = requests.post(
        url="https://archon-v0.ezkl.xyz/recipe?user_id=8c9f812f-b85e-47d6-9fca-c4f9b34622b7",
        headers={
            "X-API-KEY": secrets.ARCHON_API_KEY,
            "Content-Type": "application/json",
        },
        json={
            "commands": [
                {
                    "artifact": "balancer_fee_model",
                    "binary": "ezkl",
                    "deployment": "0195a9d3-6efb-7597-b846-3547ff9424b7",
                    "command": [
                        "gen-witness",
                        f"--data input_{LATEST_UUID}.json",
                        f"--compiled-circuit model.compiled",
                        f"--output witness_{LATEST_UUID}.json"
                    ],
                },
                {
                    "artifact": "balancer_fee_model",
                    "binary": "ezkl",
                    "deployment": "0195a9d3-6efb-7597-b846-3547ff9424b7",
                    "command": [
                        "prove",
                        f"--witness witness_{LATEST_UUID}.json",
                        f"--compiled-circuit model.compiled" ,
                        "--pk-path pk.key",
                        f"--proof-path proof_{LATEST_UUID}.json",
                    ],
                    "output_path": [f"proof_{LATEST_UUID}.json"]
                },
            ],
            "data": [{
                "target_path": f"input_{LATEST_UUID}.json",
                "data": data
            }],
        }
    )

    if res.status_code >= 400:
        print(f"Error: HTTP {res.status_code}")
        print(f"Error message: {res.content}")
    else:
        if DEBUG:
            print("Request successful")

        data = json.loads(res.content.decode('utf-8'))

        if DEBUG:
            print(f"full data: {data}")
            print(f"id: {data['id']}")

        cluster_id = data["id"]


        query_count = 0
        proof_data = None

        while query_count < 60:
            time.sleep(10)
            # get job status
            # pass id to client so client polls
            res = requests.get(
                url=f"https://archon-v0.ezkl.xyz/recipe/{str(cluster_id)}?user_id=8c9f812f-b85e-47d6-9fca-c4f9b34622b7",
                headers={
                    "X-API-KEY": secrets.ARCHON_API_KEY,
                }
            )
            res.raise_for_status()
            data = json.loads(res.content.decode('utf-8'))

            if DEBUG:
                print(f"witness data: {data[0]}")
                print(f"prove data: {data[1]}")
                print(f"prove status: {data[1]['status']}")

            status = data[1]['status']

            if status == "Complete":
                if DEBUG:
                    print(f"Complete: {data}")
                json_data = json.loads(data[1]['output'][0]['utf8_string'])

                res.raise_for_status()

                proof_data = res.json()

                if DEBUG:
                    print(f"hex_proof: {json_data['hex_proof']}")

                instances = json_data['pretty_public_inputs']['inputs'][0] + \
                    json_data['pretty_public_inputs']['outputs'][0]

                if DEBUG:
                    print(f"instances: {instances}")

                encoded_data = encode(
                    ["bytes", "uint256"],
                    [
                        Web3.to_bytes(hexstr=json_data['hex_proof']),
                        int(json_data['pretty_public_inputs']['outputs'][0][0], 16)
                    ])

                hexstr_data = Web3.to_hex(encoded_data)

                print(hexstr_data)
                break

            if status == "Errored":
                print("ERRORED")
                print(f"Error data: {data}")
                break


            query_count += 1

except Exception as e:
    print(f"Error parsing response: {str(e)}")
    print(traceback.format_exc())
