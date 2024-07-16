from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, TransportError, NotFoundError
from requests.auth import HTTPBasicAuth
import pandas as pd
import urllib3
import requests
import ssl

# Disable SSL warnings (not recommended for production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_network_logs(index_name):
    # Connect to Elasticsearch
    try:
  

        # Replace with your actual API key
        api_key = "T19Lb0taQUJueTBzSkozRWo4enI6TDVfZlVIcEpUQWU1WVo3TTVOOWM1Zw=="

        # Initialize the Elasticsearch client
        client = Elasticsearch("https://chromewell-elk-soc.es.us-central1.gcp.cloud.es.io",
        api_key=api_key
        )

     
        index_name = ".ds-logs-endpoint.events.network-default*"
        # Define the query with size inside the body
        query = {
            "size": 1000,
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.dataset": "endpoint.events.network"}},
                        {"match": {"event.action": "http_request"}}
                    ]
                }
            }
        }

        # Fetch logs from Elasticsearch
        response = client.search(index=index_name, body=query)

        # Extract destination IPs from logs
        logs = []
        for hit in response['hits']['hits']:
            logs.append(hit['_source'])

        return logs

    except ConnectionError as e:
        print(f"ConnectionError connecting to Elasticsearch: {e}")
    except TransportError as e:
        print(f"TransportError connecting to Elasticsearch: {e}")
    except NotFoundError as e:
        print(f"NotFoundError: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    return []


if __name__ == "__main__":
    logs = get_network_logs('.ds-logs-endpoint.events.network-default*')
    if logs:
        # Convert logs to pandas DataFrame
        df = pd.DataFrame(logs)
        df.to_csv('network_logs.csv', index=False)
        print("Logs have been exported to network_logs.csv")
    else:
        print("No logs found for the specified query.")
   