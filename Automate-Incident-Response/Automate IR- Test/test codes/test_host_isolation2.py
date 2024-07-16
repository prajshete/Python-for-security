
import requests
import json
import pandas as pd


'''
def get_endpoint_id(base_url, headers, host_name):

    endpoint = f"{base_url}/api/endpoint/metadata"
    response = requests.get(endpoint, headers=headers)
    
    if response.status_code == 200:
        endpoints = response.json()
        for endpoint in endpoints['data']:
            if endpoint['host']['hostname'] == host_name:
                return endpoint['agent']['id']
        return None

    else:
        print(f"Failed to retrieve endpoints. Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        return None
'''


# Function to isolate a host
def isolate_host():

    ELASTIC_BASE_URL = "https://chromewell-elk-soc.es.us-central1.gcp.cloud.es.io"  # Replace with your Elastic instance URL
    API_KEY = "T19Lb0taQUJueTBzSkozRWo4enI6TDVfZlVIcEpUQWU1WVo3TTVOOWM1Zw=="  # Replace with your Elastic API key
    output_excel_http = "C:/Users/prajs_28/OneDrive/Desktop/PKF ALgosmic/Automate IR/Automate-Incident-Response/CSV Results/output_http.xlsx"


    headers = {
        "Content-Type": "application/json",
        "Authorization": f"ApiKey {API_KEY}"   
    }

    curl_command = [
        "curl", "-XPOST", endpoint,
        "-H", "kbn-xsrf: reporting",
        "-H", "Content-Type: application/json",
        "-d", json.dumps(payload)
    ]

    result = subprocess.run(curl_command, capture_output=True, text=True)

    
    df = pd.read_excel(output_excel_http)
    for index, row in df.iterrows():
        host_name = row['host.name']
        if row['Type'] == "confirmed_malicious":
                endpoint = f"{ELASTIC_BASE_URL}/api/endpoint/action/isolate"
                payload = {
                    "endpoint_ids": "dc708d94-2c66-4dd3-b127-498df66ae6e5"
                }

                response = requests.post(endpoint, headers=headers, data=json.dumps(payload))

                if response.status_code == 200:
                    print(f"Host {host_name} has been successfully isolated.")
                else:
                    print(f"Failed to isolate host {host_name}. Status Code: {response.status_code}")
                    print(f"Response: {response.text}")

def main():
    # Isolate the host
    isolate_host()

if __name__== "__main__":
    main()


'''
import requests

def check_base_url(base_url, api_key):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"ApiKey {api_key}"
    }
    
    endpoint = f"{base_url}/_cluster/health"
    response = requests.get(endpoint, headers=headers)
    
    if response.status_code == 200:
        print("Base URL is correct.")
        print("Cluster Health:", response.json())
    else:
        print(f"Failed to reach the cluster health endpoint. Status Code: {response.status_code}")
        print(f"Response: {response.text}")

# Replace with your actual base URL and API key
base_url = "https://chromewell-elk-soc.es.us-central1.gcp.cloud.es.io:9243"
api_key = "T19Lb0taQUJueTBzSkozRWo4enI6TDVfZlVIcEpUQWU1WVo3TTVOOWM1Zw=="

check_base_url(base_url, api_key)
'''