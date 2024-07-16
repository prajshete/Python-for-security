
import subprocess
import json
import pandas as pd
import time


# Function to get endpoint ID using curl command
def get_endpoint_id(base_url, api_key, host_name):

    endpoint = f"{base_url}/api/endpoint/metadata"
    
    # Construct the curl command
    curl_command = [
        "curl", "-s", "-XGET", endpoint,
        "-H", "kbn-xsrf: reporting",
        "-H", f"Authorization: ApiKey {api_key}"
    ]

    result = subprocess.run(curl_command, capture_output=True, text=True)
    #print(result)

    
    if result.returncode == 0:
        endpoints_data = json.loads(result.stdout)
        endpoints=endpoints_data["data"]

        for endpoint in endpoints:
            metadata = endpoint.get('metadata', {})
            host_info = metadata.get('host', {})
            hostname = host_info.get('hostname')

            if hostname == host_name:
                agent_id = metadata.get('agent', {}).get('id')
                return agent_id
            else:
                print(f"Host '{host_name}' not found in endpoint metadata.")
                return None
        
    else:
        print(f"Failed to retrieve endpoints. Return Code: {result.returncode}")
        print(f"Response: {result.stderr}")
        return None


# Function to isolate a host using curl command
def isolate_host(base_url, api_key, endpoint_id, host_name):
    
    endpoint = f"{base_url}/api/endpoint/action/isolate"
    payload = {
        "endpoint_ids": [endpoint_id]
    }

    # Construct the curl command
    
    curl_command = [
        "curl", "-s", "-XPOST", endpoint,
        "-H", "kbn-xsrf: reporting",
        "-H", "Content-Type: application/json",
        "-H", f"Authorization: ApiKey {api_key}",
        "-d", json.dumps(payload)
    ]

    subprocess.run(curl_command, capture_output=True, text=True)
    
    time.sleep(120)
    
    result_isolate = f"{base_url}/api/endpoint/action"

    curl_command2 = [
        "curl", "-s", "-XGET", result_isolate,
        "-H", "kbn-xsrf: reporting",
        "-H", "Content-Type: application/json",
        "-H", f"Authorization: ApiKey {api_key}"
    ]

    result = subprocess.run(curl_command2, capture_output=True, text=True)
    
    if result.returncode == 0:
        response = json.loads(result.stdout)

        for item in response["data"]:
            command = item.get("command")
            was_successful = item.get("wasSuccessful")

            if command == "isolate" and was_successful:
                isolation_successful = True
                print(f"\nHost {host_name} has been successfully isolated !\n")
                break
        
        if not isolation_successful:
            print(f"Failed to isolate host {host_name}.")

    else:
        print(f"Failed to isolate host {host_name}. Return Code: {result.returncode}")
        print(f"Response: {result.stderr}")


def main():
    ELASTIC_BASE_URL = "https://chromewell-elk-soc.kb.us-central1.gcp.cloud.es.io:9243"
    API_KEY = "T19Lb0taQUJueTBzSkozRWo4enI6TDVfZlVIcEpUQWU1WVo3TTVOOWM1Zw=="  # Replace with your Elastic API key
    output_excel_http = "C:/Users/prajs_28/OneDrive/Desktop/PKF ALgosmic/Automate IR/Automate-Incident-Response/CSV Results/output_http.xlsx"

    df = pd.read_excel(output_excel_http)
    for index, row in df.iterrows():
        host_name = row['host.name']
        if row['Type'] == "confirmed_malicious":
            endpoint_id = get_endpoint_id(ELASTIC_BASE_URL, API_KEY, host_name)
            if endpoint_id is None:
                print(f"Endpoint ID not found for host {host_name}.")
            else:
                isolate_host(ELASTIC_BASE_URL, API_KEY, endpoint_id, host_name)


if __name__== "__main__":
    main()
