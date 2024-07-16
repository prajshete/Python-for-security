from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, TransportError, NotFoundError
from requests.auth import HTTPBasicAuth
import pandas as pd
import urllib3
import requests
import ssl
import vt
import os 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



# ========================== GET LOGS FROM ELASTIC SEARCH ========================


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
                        {"match": {"event.action": "http_request"}},
                        {"match": {"process.name": "OUTLOOK.EXE"}}
                    ],
                    "must_not": [
                        {"match": {"source.ip": "127.0.0.1"}},
                        {"terms": {"destination.ip": ["13.127.228.11", "40.100.141.168", "40.100.72.65", "52.98.88.72"]}},
                        {"match": {"user.name": "SYSTEM"}},
                        {"match": {"user.name": "NETWORK SERVICE"}},
                        #{"regexp": {"source.ip": "[0-9a-fA-F]{2}([-:.])[0-9a-fA-F]{2}(\\1[0-9a-fA-F]{2}){4}"}},
                        #{"regexp": {"destination.ip": "[0-9a-fA-F]{2}([-:.])[0-9a-fA-F]{2}(\\1[0-9a-fA-F]{2}){4}"}},
                        {
                            "range": {
                                "destination.ip": {
                                    "gte": "192.168.0.0",
                                    "lte": "192.168.255.255"
                                }
                            }
                        }
                    ]
                }
            }
        }


        # Fetch logs from Elasticsearch
        response = client.search(index=index_name, body=query)

        # Extract destination IPs from logs
        logs = []
        for hit in response['hits']['hits']:
            source = hit['_source']
            logs.append({
                'user.name': source.get('user', {}).get('name', None),
                'process.name': source.get('process', {}).get('name', None),
                'host.name': source.get('host', {}).get('name', None),
                'event.action': source.get('event', {}).get('action', None),
                'source.ip': source.get('source', {}).get('ip', None),
                'destination.ip': source.get('destination', {}).get('ip', None),
                'http.request.body.content': source.get('http', {}).get('request', {}).get('body', {}).get('content', None)
            })

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


#================= CHECKS IP ADDRESSES FOR HITS ON VIRUSTOTALS ===================


def check_ip_virustotal(ip, vt_client):
    try:
        vt_result = vt_client.get_object(f"/ip_addresses/{ip}")
        # Extracting community score from the result
        if hasattr(vt_result, 'last_analysis_stats'):
            community_score = vt_result.last_analysis_stats['malicious']
            return community_score
        else:
            return None
    except vt.APIError as e:
        print(f"VirusTotal API Error: {e}")
    return None

def extract_dns(http_request_body_content):
    if http_request_body_content and "Host:" in http_request_body_content:
        return http_request_body_content.split("Host:")[1].strip().split()[0]
    return None



 #======================== MAIN ===========================


if __name__ == "__main__":

    xls_dir = "C:/Users/prajs_28/OneDrive/Desktop/PKF ALgosmic/excel_logs"
    excel_file_path = os.path.join(xls_dir, "network_logs.xlsx")

    # RETRIEVE LOGS AND SAVE AS EXCEL
    logs = get_network_logs('.ds-logs-endpoint.events.network-default*')
    if logs:
        # Convert logs to pandas DataFrame
        df = pd.DataFrame(logs)
        df['dns'] = df['http.request.body.content'].apply(extract_dns)
        df.drop(columns=['http.request.body.content'], inplace=True)
        df.to_excel(excel_file_path, index=False)
        print("Logs have been exported to network_logs.xls")
    else:
        print("No logs found for the specified query.")



    # Load Excel file into pandas dataframe
    excel_file = excel_file_path  # Replace with your actual Excel file name
    df = pd.read_excel(excel_file)

    # Remove duplicates from last destination.ip column
    df.drop_duplicates(subset=['destination.ip'], keep='last', inplace=True)



    #FOR TESTING PURPOSE..COMMENT OUT THIS SECTION IN ACTUAL PRODUCTION
#===============================================================================
    df = df.head(5) 
    df.to_excel(excel_file_path, index=False)
    print("Logs have been reduced")
#===============================================================================
    



    # Initialize VirusTotal client
    vt_client = vt.Client("64d95710638db1d65f00a6e283175deca63f7ad4b9b7aafc47fedc0a30ccf827")  # Replace with your actual VirusTotal API key

    # Iterate through unique destination IPs and check with VirusTotal
    results = []
    for ip in df['destination.ip'].unique():
        community_score = check_ip_virustotal(ip, vt_client)
        if community_score is not None:
            if community_score > 0:
            # Get corresponding user.name and host.name from the Excel if community score > 0
                user_name = df.loc[df['destination.ip'] == ip, 'user.name'].iloc[0]
                host_name = df.loc[df['destination.ip'] == ip, 'host.name'].iloc[0]
                results.append({
                    'IP': ip,
                    'Community Score': community_score,
                    'User Name': user_name,
                    'Host Name': host_name
                })
        else:
            print(f"Could not get VirusTotal community score for IP: {ip}")

# Print or do something with the results
for result in results:
    print(f"IP: {result['IP']}")
    print(f"Community Score: {result['Community Score']}")
    print(f"User Name: {result['User Name']}")
    print(f"Host Name: {result['Host Name']}")
    print()

vt_client.close()
