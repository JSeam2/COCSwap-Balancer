"""
Utility code to test the update lilith logic. This is mostly meant for testing purposes.
Use cronjob.py for production.
"""
import uuid
import secrets
import requests
import json
from updatefee import logger
import traceback
import time


def call_lilith():
    latest_uuid = str(uuid.uuid4())

    with open("input_debug.json", "r") as f:
        d = json.load(f)

    try:
        res = requests.post(
            url=f"{secrets.ARCHON_URL}/recipe?user_id=8c9f812f-b85e-47d6-9fca-c4f9b34622b7",
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
                            f"--data input_{latest_uuid}.json",
                            f"--compiled-circuit model.compiled",
                            f"--output witness_{latest_uuid}.json"
                        ],
                    },
                    {
                        "artifact": "balancer_fee_model",
                        "binary": "ezkl",
                        "deployment": "0195a9d3-6efb-7597-b846-3547ff9424b7",
                        "command": [
                            "prove",
                            f"--witness witness_{latest_uuid}.json",
                            f"--compiled-circuit model.compiled" ,
                            "--pk-path pk.key",
                            f"--proof-path proof_{latest_uuid}.json",
                        ],
                        "output_path": [f"proof_{latest_uuid}.json"]
                    },
                ],
                "data": [{
                    "target_path": f"input_{latest_uuid}.json",
                    "data": d
                }],
            }
        )

        if res.status_code >= 400:
            logger.error(f"Error: HTTP {res.status_code}")
            logger.error(f"Error message: {res.content}")
        else:
            logger.info("Request successful")

            data = json.loads(res.content.decode('utf-8'))
            logger.info(f"full data: {data}")
            logger.info(f"id: {data['id']}")

            cluster_id = data["id"]


            query_count = 0
            proof_data = None

            while query_count < 60:
                time.sleep(10)
                # get job status
                # pass id to client so client polls
                res = requests.get(
                    url=f"{secrets.ARCHON_URL}/recipe/{str(cluster_id)}?user_id=8c9f812f-b85e-47d6-9fca-c4f9b34622b7",
                    headers={
                        "X-API-KEY": secrets.ARCHON_API_KEY,
                    }
                )
                res.raise_for_status()
                data = json.loads(res.content.decode('utf-8'))
                logger.info(f"witness data: {data[0]}")
                logger.info(f"prove data: {data[1]}")
                logger.info(f"prove status: {data[1]['status']}")

                status = data[1]['status']

                if status == "Complete":
                    logger.info(f"Complete: {data}")
                    json_data = json.loads(data[1]['output'][0]['utf8_string'])

                    res.raise_for_status()

                    proof_data = res.json()

                    logger.info(f"hex_proof: {json_data['hex_proof']}")

                    instances = json_data['pretty_public_inputs']['inputs'][0] + \
                        json_data['pretty_public_inputs']['outputs'][0]

                    logger.info(f"instances: {instances}")

                    return json_data['hex_proof'], instances

                if status == "Errored":
                    logger.error("ERRORED")
                    logger.error(f"Error data: {data}")
                    break


                query_count += 1

    except Exception as e:
        logger.error(f"Error parsing response: {str(e)}")
        logger.error(traceback.format_exc())


if __name__ == "__main__":
    call_lilith()