from elasticsearch import Elasticsearch

# Replace with your actual API key
api_key = "T19Lb0taQUJueTBzSkozRWo4enI6TDVfZlVIcEpUQWU1WVo3TTVOOWM1Zw=="

# Initialize the Elasticsearch client
client = Elasticsearch(
    "https://chromewell-elk-soc.es.us-central1.gcp.cloud.es.io",
    api_key=api_key
)

# Retrieve the list of indices
indices_info = client.cat.indices(format='json')

# Extract and print the names of the indices
index_names = [index['index'] for index in indices_info]

if '.ds-logs-endpoint.events.network-default-2024.06.09-000376' in index_names:
            #logs = get_network_logs(client, '.ds-logs-endpoint.events.network-default-2024.06.09-000376')
    print("index found")
else:
    print("The specified index was not found in the list of indices.")


#print("List of indices:")
#for index_name in index_names:
#    print(index_name)