from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, TransportError, NotFoundError
import urllib3
import ssl

# Disable SSL warnings (not recommended for production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def list_indices(client):
    try:
        indices = client.cat.indices(format='json')
        print("Indices in Elasticsearch:")
        for index in indices:
            print(index['index'])
        return [index['index'] for index in indices]
    except Exception as e:
        print(f"An error occurred while listing indices: {e}")
        return []

def get_network_logs(client, index_name):
    try:
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
    try:
        # Replace with your actual API key
        api_key = "T19Lb0taQUJueTBzSkozRWo4enI6TDVfZlVIcEpUQWU1WVo3TTVOOWM1Zw=="

        # Initialize the Elasticsearch client
        client = Elasticsearch(
            "https://chromewell-elk-soc.kb.us-central1.gcp.cloud.es.io",
            api_key=api_key,
            #scheme="https"
        )

        # List all indices
        index_names = list_indices(client)
        print(index_names)

        # Use the correct index name from the list
        if '.lists-default-000001' in index_names:
            #logs = get_network_logs(client, '.ds-logs-endpoint.events.network-default-2024.06.09-000376')
            print("index found")
        else:
            print("The specified index was not found in the list of indices.")

    except Exception as e:
        print(f"An error occurred: {e}")
