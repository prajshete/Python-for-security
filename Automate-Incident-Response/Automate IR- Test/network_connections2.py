from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, TransportError, NotFoundError
from requests.auth import HTTPBasicAuth
import pandas as pd
import urllib3
import requests
import ssl
import vt
import os 
import asyncio
import time
import typer
#from my_module import get_http_network_logs, get_dns_network_logs, extract_dns, process_logs_http, process_logs_dns


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = typer.Typer()
# ========================== GET LOOKUP_RESULT LOGS FROM ELASTIC SEARCH ========================

#@app.command()
def get_dns_network_logs(index_name, timestamp: str):
    # Connect to Elasticsearch
    try:
        # Replace with your actual API key
        api_key = "T19Lb0taQUJueTBzSkozRWo4enI6TDVfZlVIcEpUQWU1WVo3TTVOOWM1Zw=="

        # Initialize the Elasticsearch client
        client = Elasticsearch("https://chromewell-elk-soc.es.us-central1.gcp.cloud.es.io",
        api_key=api_key
        )

        if timestamp.endswith('h'):
            hours = int(timestamp[:-1])
     
        index_name = ".ds-logs-endpoint.events.network-default*"
        # Define the query with size inside the body
        query = {
            "size": 1000,
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.dataset": "endpoint.events.network"}},
                        {"match": {"event.action": "lookup_result"}},
                        {"match": {"process.name": "chrome.exe"}},
                        {"range":{"@timestamp":{"gte": f"now-{hours}h","lte": "now/h"}}}
                    ],
                    "must_not": [
                        
                        {"query_string": {"query": "dns.question.name:*chromewell* OR dns.question.name:*ocsp* OR dns.question.name:*ctldl.windowsupdate.com* OR dns.question.name:*google* OR dns.question.name:*wpad* OR dns.question.name:*whatsapp* OR dns.question.name:*mozilla* OR dns.question.name:*amazon* OR dns.question.name:*facebook* OR dns.question.name:*linkedin* OR dns.question.name:*youtube* OR dns.question.name:*static* OR dns.question.name:*gov* OR dns.question.name:*fullview* OR dns.question.name:*twitter* OR dns.question.name:*weather.service.msn.com* OR dns.question.name:*microsoft* OR dns.question.name:*johndeere.com* OR dns.question.name:*microsoftonline.com*"}},
                        {"terms": {"user.name": ["SYSTEM", "NETWORK SERVICE", "USER", "adity", "Dell"]}},
                        #{"regexp": {"source.ip": "[0-9a-fA-F]{2}([-:.])[0-9a-fA-F]{2}(\\1[0-9a-fA-F]{2}){4}"}},
                        #{"regexp": {"destination.ip": "[0-9a-fA-F]{2}([-:.])[0-9a-fA-F]{2}(\\1[0-9a-fA-F]{2}){4}"}},
                        {"range": {"destination.ip": {"gte": "192.168.0.0","lte": "192.168.255.255"}}}
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
                'dns.question.name': source.get('dns', {}).get('question', {}).get('name', None)
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
#==============================================================================================

# ========================== GET HTTP_REQUEST LOGS FROM ELASTIC SEARCH ========================

#@app.command()
def get_http_network_logs(index_name, timestamp: str):
    # Connect to Elasticsearch
    try:
        # Replace with your actual API key
        api_key = "T19Lb0taQUJueTBzSkozRWo4enI6TDVfZlVIcEpUQWU1WVo3TTVOOWM1Zw=="

        # Initialize the Elasticsearch client
        client = Elasticsearch("https://chromewell-elk-soc.es.us-central1.gcp.cloud.es.io",
        api_key=api_key
        )

        if timestamp.endswith('h'):
            hours = int(timestamp[:-1])
        index_name = ".ds-logs-endpoint.events.network-default*"
        # Define the query with size inside the body
        query = {
            "size": 1000,
            "query": {
                "bool": {
                    "must": [
                        {"match": {"event.dataset": "endpoint.events.network"}},
                        {"match": {"event.action": "http_request"}},
                        {"terms": {"process.name": ["chrome.exe","OUTLOOK.EXE"]}},
                        {"range":{"@timestamp":{"gte": f"now-{hours}h","lte": "now/h"}}}
                    ],
                    "must_not": [
                        {"match": {"source.ip": "127.0.0.1"}},
                        {"terms": {"destination.ip": ["13.127.228.11", "40.100.0.0/16", "52.98.88.72", "142.250.0.0/16", "142.251.0.0/16", "192.168.0.0/16", "172.18.0.0/16", "127.0.0.1", "13.127.228.11", "172.31.0.0/16", "210.16.92.198", "103.36.71.187", "23.217.0.0/15"]}},
                        {"query_string": {"query": "http.request.body.content:*chromewell* OR http.request.body.content:*ocsp* OR http.request.body.content:*ctldl.windowsupdate.com* OR http.request.body.content:*google* OR http.request.body.content:*wpad* OR http.request.body.content:*whatsapp* OR http.request.body.content:*mozilla* OR http.request.body.content:*amazon* OR http.request.body.content:*facebook* OR http.request.body.content:*linkedin* OR http.request.body.content:*youtube* OR http.request.body.content:*static* OR http.request.body.content:*gov* OR http.request.body.content:*fullview* OR http.request.body.content:*twitter* OR http.request.body.content:*weather.service.msn.com* OR http.request.body.content:*microsoft* OR http.request.body.content:*johndeere.com*"}},
                        {"terms": {"user.name": ["SYSTEM", "NETWORK SERVICE", "USER", "adity", "Dell"]}},
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

#=================================================================================


#================= CHECKS DNS FOR HITS ON VIRUSTOTALS ============================

def check_dns_virustotal(dns, vt_client):
    try:
        vt_result = vt_client.get_object(f"/domains/{dns}")
        if hasattr(vt_result, 'last_analysis_stats'):
            community_score = vt_result.last_analysis_stats['malicious']
            return community_score
        else:
            return None
    except vt.APIError as e:
        print(f"VirusTotal API Error: {e}")
    return None

#=================================================================================


#==================== EXTRACTS DNS FROM FIELD ====================================

def extract_dns(http_request_body_content):
    if http_request_body_content and "Host:" in http_request_body_content:
        return http_request_body_content.split("Host:")[1].strip().split()[0]
    return None

#=================================================================================

# ================== Iterate through unique destination IPs and check with VirusTotal ==========================


def process_logs_http(vt_client, df):
    confirmed_mal_results = []
    sus_mal_results = []
    clean_results = []
    for ip in df['destination.ip'].unique():
        community_score = check_ip_virustotal(ip, vt_client)
        if community_score is not None:
            user_name = df.loc[df['destination.ip'] == ip, 'user.name'].iloc[0]
            host_name = df.loc[df['destination.ip'] == ip, 'host.name'].iloc[0]
            dns = df.loc[df['destination.ip'] == ip, 'dns'].iloc[0]
            if community_score >= 8:
                
                confirmed_mal_results.append({
                    'IP': ip,
                    'Community Score': community_score,
                    'User Name': user_name,
                    'Host Name': host_name,
                    'Status': 'Confirmed malicious'
                })
            elif 1 < community_score <= 5:
                
                dns_score = check_dns_virustotal(dns, vt_client)
                if dns_score is not None:
                    sus_mal_results.append({
                        'IP': ip,
                        'Community Score': community_score,
                        'DNS': dns,
                        'DNS Score': dns_score,
                        'User Name': user_name,
                        'Host Name': host_name
                    })
                else:
                    sus_mal_results.append({
                        'IP': ip,
                        'Community Score': community_score,
                        'User Name': user_name,
                        'Host Name': host_name
                    })
            elif community_score == 0:
                dns_score = check_dns_virustotal(dns, vt_client)
                if dns_score != 0:
                    sus_mal_results.append({
                        'IP': ip,
                        'Community Score': community_score,
                        'DNS': dns,
                        'DNS Score': dns_score,
                        'User Name': user_name,
                        'Host Name': host_name
                    })
                else:
                    clean_results.append({
                        'IP': ip,
                        'Community Score': community_score,
                        'User Name': user_name,
                        'Host Name': host_name
                    })


        else:
            print(f"Could not get VirusTotal community score for IP: {ip}")

    # Print confirmed malicious results
    print("================================")
    print("     CONFIRMED MALICIOUS        ")
    print("================================")
    for result in confirmed_mal_results:
        
        print(f"IP: {result['IP']}")
        print(f"Community Score: {result['Community Score']}")
        print(f"User Name: {result['User Name']}")
        print(f"Host Name: {result['Host Name']}")
        print(f"Status: {result['Status']}")
        print()

    # Print suspicious results
    print("============================================")
    print("    SUSPICIOUS - INVESTIGATION REQUIRED     ")
    print("============================================")
    for result in sus_mal_results:
        print(f"IP: {result['IP']}")
        print(f"Community Score: {result['Community Score']}")
        print(f"User Name: {result['User Name']}")
        print(f"Host Name: {result['Host Name']}")
        if 'DNS' in result:
            print(f"DNS: {result['DNS']}")
            print(f"DNS Score: {result['DNS Score']}")
        print()

    print("=========================")
    print("         CLEAN           ")
    print("=========================")
    for result in clean_results:
        
        print(f"IP: {result['IP']}")
        print(f"Community Score: {result['Community Score']}")
        print()

#======================================================================================================




# ================== Iterate through unique DNS and check with VirusTotal ==========================


def process_logs_dns(vt_client, df):
    confirmed_mal_results = []
    sus_mal_results = []
    clean_results = []
    for dns in df['dns.question.name'].unique():
        community_score = check_dns_virustotal(dns, vt_client)
        if community_score is not None:
            user_name = df.loc[df['dns.question.name'] == dns, 'user.name'].iloc[0]
            host_name = df.loc[df['dns.question.name'] == dns, 'host.name'].iloc[0]
            dns = df.loc[df['dns.question.name'] == dns, 'dns.question.name'].iloc[0]
            if community_score >= 5:    
                confirmed_mal_results.append({
                    'DNS': dns,
                    'DNS Community Score': community_score,
                    'User Name': user_name,
                    'Host Name': host_name,
                    'Status': 'Confirmed malicious'
                })
            elif 1 < community_score < 5:
                sus_mal_results.append({
                    'DNS': dns,
                    'DNS Community Score': community_score,
                    'User Name': user_name,
                    'Host Name': host_name
                })
            elif community_score == 0:
                clean_results.append({
                    'DNS': dns,
                    'DNS Community Score': community_score,
                })
        else:
            print(f"Could not get VirusTotal community score for DNS: {dns}")

    # Print confirmed malicious results
    print("================================")
    print("     CONFIRMED MALICIOUS        ")
    print("================================")
    for result in confirmed_mal_results:
        
        print(f"DNS: {result['DNS']}")
        print(f"Community Score: {result['DNS Community Score']}")
        print(f"User Name: {result['User Name']}")
        print(f"Host Name: {result['Host Name']}")
        print(f"Status: {result['Status']}")
        print()

    # Print suspicious results
    print("============================================")
    print("    SUSPICIOUS - INVESTIGATION REQUIRED     ")
    print("============================================")
    for result in sus_mal_results:
        print(f"DNS: {result['DNS']}")
        print(f"DNS Community Score: {result['DNS Community Score']}")
        print(f"User Name: {result['User Name']}")
        print(f"Host Name: {result['Host Name']}")
        print()

    print("=========================")
    print("         CLEAN           ")
    print("=========================")
    for result in clean_results:
        
        print(f"DNS: {result['DNS']}")
        print(f"DNS Community Score: {result['DNS Community Score']}")
        print()

#======================================================================================================




 #======================== MAIN ===========================
@app.command()
def main(timestamp: str = typer.Option(..., help="Timestamp range for the query, e.g., '24h', '48h', etc.")):

    xls_dir = "C:/Users/prajs_28/OneDrive/Desktop/PKF ALgosmic/excel_logs"
    excel_file_path_http = os.path.join(xls_dir, "http_network_logs.xlsx")
    excel_file_path_dns = os.path.join(xls_dir, "dns_network_logs.xlsx")

    # RETRIEVE LOGS AND SAVE AS EXCEL
    logs_http = get_http_network_logs('.ds-logs-endpoint.events.network-default*', timestamp)
    if logs_http:
        # Convert logs to pandas DataFrame
        df_http = pd.DataFrame(logs_http)
        df_http['dns'] = df_http['http.request.body.content'].apply(extract_dns)
        df_http.drop(columns=['http.request.body.content'], inplace=True)
        df_http.drop_duplicates(subset=['destination.ip'], keep='last', inplace=True)
        df_http.to_excel(excel_file_path_http, index=False)
        print("HTTP logs have been exported to http_network_logs.xls\n\n")
    else:
        print("No logs found for the specified query.")


    logs_dns = get_dns_network_logs('.ds-logs-endpoint.events.network-default*',timestamp)
    if logs_dns:
        # Convert logs to pandas DataFrame
        df_dns = pd.DataFrame(logs_dns)
        df_dns.drop_duplicates(subset=['dns.question.name'], keep='last', inplace=True)
        df_dns.to_excel(excel_file_path_dns, index=False)
        print("DNS logs have been exported to dns_network_logs.xls\n\n")
    else:
        print("No logs found for the specified query.")


    #FOR TESTING PURPOSE..COMMENT OUT THIS SECTION IN ACTUAL PRODUCTION
    #===============================================================================
    #df = df.head(5) 
    #df.to_excel(excel_file_path, index=False)
    #print("Logs have been reduced")
    #===============================================================================

    vt_client = vt.Client("64d95710638db1d65f00a6e283175deca63f7ad4b9b7aafc47fedc0a30ccf827")

    df_http = pd.read_excel(excel_file_path_http)
    print("************************** RESULTS OF HTTP NETWORK CONNECTIONS ***************************\n\n")
    process_logs_http(vt_client, df_http)

    time.sleep(5)
    df_dns = pd.read_excel(excel_file_path_dns)
    print("************************** RESULTS OF DNS NETWORK CONNECTIONS ***************************\n\n")
    process_logs_dns(vt_client, df_dns)

    vt_client.close()


if __name__ == "__main__":
   app()
   

   
    
