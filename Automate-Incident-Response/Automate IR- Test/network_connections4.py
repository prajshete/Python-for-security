from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, TransportError, NotFoundError
from requests.auth import HTTPBasicAuth
import pandas as pd
import urllib3,requests, ssl, vt, os, asyncio, time, typer, json

#from my_module import get_http_network_logs, get_dns_network_logs, extract_dns, process_logs_http, process_logs_dns


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = typer.Typer()


#=============== Function to read FP domains from excel file =========================

def read_false_positive_domains(excel_path, sheet_name='Sheet1'):
    # Read the Excel file
    df = pd.read_excel(excel_path, sheet_name=sheet_name)
    # Assuming the first column contains the false positive domains
    domains = df.iloc[:, 0].tolist()
    return domains

#=====================================================================================


#=============== Function to read FP domains from excel file =========================

def build_elasticsearch_query_dns(domains):
    # Build the query string
    query_string_dns = " OR ".join([f"dns.question.name:{domain}" for domain in domains])
    #query_string_dns = f'({query_string_dns})'
    return query_string_dns

#=====================================================================================


#=============== Function to read FP domains from excel file =========================

def build_elasticsearch_query_http(domains):
    # Build the query string
    query_string_http = " OR ".join([f"http.request.body.content:{domain}" for domain in domains])
    return query_string_http

#=====================================================================================

 

# ========================== GET LOOKUP_RESULT LOGS FROM ELASTIC SEARCH ========================

#@app.command()
def get_dns_network_logs(index_name, timestamp: str, fp_domain_query_dns):
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
        query = f'''
        {{
            "size": 1000,
            "query": {{
                "bool": {{
                    "must": [
                        {{"match": {{"event.dataset": "endpoint.events.network"}}}},
                        {{"match": {{"event.action": "lookup_result"}}}},
                        {{"terms": {{"process.name": ["chrome.exe", "OUTLOOK.EXE"]}}}},
                        {{"range": {{"@timestamp": {{"gte": "now-{hours}h", "lte": "now/h"}}}}}}
                    ],
                    "must_not": [
                        {{"query_string": {{"query": "{fp_domain_query_dns}"}}}},
                        {{"terms": {{"user.name": ["SYSTEM", "NETWORK SERVICE", "USER", "adity", "Dell"]}}}},
                        {{
                            "range": {{
                                "destination.ip": {{
                                    "gte": "192.168.0.0",
                                    "lte": "192.168.255.255"
                                }}
                            }}
                        }}
                    ]
                }}
            }}
        }}
        '''

        
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
def get_http_network_logs(index_name, timestamp: str, fp_domain_query_http):
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

        query = f'''
        {{
            "size": 1000,
            "query": {{
                "bool": {{
                    "must": [
                        {{"match": {{"event.dataset": "endpoint.events.network"}}}},
                        {{"match": {{"event.action": "http_request"}}}},
                        {{"terms": {{"process.name": ["chrome.exe", "OUTLOOK.EXE"]}}}},
                        {{"range": {{"@timestamp": {{"gte": "now-{hours}h", "lte": "now/h"}}}}}}
                    ],
                    "must_not": [
                        {{"match": {{"source.ip": "127.0.0.1"}}}},
                        {{"terms": {{"destination.ip": ["13.127.228.11", "40.100.0.0/16", "52.98.88.72", "142.250.0.0/16", "142.251.0.0/16", "192.168.0.0/16", "172.18.0.0/16", "127.0.0.1", "13.127.228.11", "172.31.0.0/16", "210.16.92.198", "103.36.71.187", "23.217.0.0/15"
                     ]}}}},
                        {{"query_string": {{"query": "{fp_domain_query_http}"}}}},
                        {{"terms": {{"user.name": ["SYSTEM", "NETWORK SERVICE", "USER", "adity", "Dell"]}}}},
                        {{
                            "range": {{
                                "destination.ip": {{
                                    "gte": "192.168.0.0",
                                    "lte": "192.168.255.255"
                                }}
                            }}
                        }}
                    ]
                }}
            }}
        }}
        '''
        
        #print(query)

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

#==============================================================================================




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
    final_results_http = []


#------------------------------- Call Vt and assign score ---------------------------------------


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

    return final_results_http

#======================================================================================================




# ================== Iterate through unique DNS and check with VirusTotal ==========================


def process_logs_dns(vt_client, df):
    confirmed_mal_results = []
    sus_mal_results = []
    clean_results = []
    final_results_dns=[]


#------------------------------- Call Vt and assign score ---------------------------------------

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


    final_results_dns={
        'malicious_dns': confirmed_mal_results,
        'suspicious_dns': sus_mal_results,
        'clean_dns': clean_results
    }

    return final_results_dns

#======================================================================================================




 #================================== MAIN ========================================


@app.command()
def main(timestamp: str = typer.Option(..., help="Timestamp range for the query, e.g., '24h', '48h', etc.")):

#------------------------- Declarations -------------------------------------------------------

    final_results_http=[]
    final_results_dns=[]
    final_results=[]
    xls_dir = "C:/Users/prajs_28/OneDrive/Desktop/PKF ALgosmic/excel_logs"
    excel_file_path_http = os.path.join(xls_dir, "http_network_logs.xlsx")
    excel_file_path_dns = os.path.join(xls_dir, "dns_network_logs.xlsx")

#----------------------------------------------------------------------------------------------



#---------------- Elastic Query Builder Code snippet ------------------------------------------
    excel_file_path_fp_domains = 'false_positive_domains.xlsx'
    # Read domains from Excel
    domains = read_false_positive_domains(excel_file_path_fp_domains)

    # Build Elasticsearch query
    es_query_dns = build_elasticsearch_query_dns(domains)
    # Convert query to JSON format
    #es_query_json_dns = json.dumps(es_query_dns, indent=2)

    es_query_http = build_elasticsearch_query_http(domains)
    #es_query_json_http = json.dumps(es_query_http, indent=2)
#----------------------------------------------------------------------------------------------




#-------------------------- RETRIEVE LOGS AND SAVE AS EXCEL------------------------------------

    logs_http = get_http_network_logs('.ds-logs-endpoint.events.network-default*', timestamp, es_query_http)
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


    logs_dns = get_dns_network_logs('.ds-logs-endpoint.events.network-default*',timestamp, es_query_dns)
    if logs_dns:
        # Convert logs to pandas DataFrame
        df_dns = pd.DataFrame(logs_dns)
        df_dns.drop_duplicates(subset=['dns.question.name'], keep='last', inplace=True)
        df_dns.to_excel(excel_file_path_dns, index=False)
        print("DNS logs have been exported to dns_network_logs.xls\n\n")
    else:
        print("No logs found for the specified query.")

    
#--------------------------------------------------------------------------------------------------



    #FOR TESTING PURPOSE..COMMENT OUT THIS SECTION IN ACTUAL PRODUCTION
    #===============================================================================
    df = df.head(5) 
    df.to_excel(excel_file_path_http, index=False)
    print("HTTP Logs have been reduced")
    #===============================================================================


    #FOR TESTING PURPOSE..COMMENT OUT THIS SECTION IN ACTUAL PRODUCTION
    #===============================================================================
    df = df.head(5) 
    df.to_excel(excel_file_path_dns, index=False)
    print("DNS Logs have been reduced")
    #===============================================================================


#----------------------------- Calling VT and storing results ---------------------------------------
    vt_client = vt.Client("64d95710638db1d65f00a6e283175deca63f7ad4b9b7aafc47fedc0a30ccf827")

    df_http = pd.read_excel(excel_file_path_http)
    print("************************** RESULTS OF HTTP NETWORK CONNECTIONS ***************************\n\n")
    final_results_http=process_logs_http(vt_client, df_http)

    time.sleep(5)
    df_dns = pd.read_excel(excel_file_path_dns)
    print("************************** RESULTS OF DNS NETWORK CONNECTIONS ***************************\n\n")
    final_results_dns=process_logs_dns(vt_client, df_dns)

    final_results = {
        'http': final_results_http,
        'dns': final_results_dns
    }

#---------------------------------------------------------------------------------------------------------

    vt_client.close()


if __name__ == "__main__":
   app()
  

   
    























































