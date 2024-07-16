import pandas as pd
import vt
import asyncio

# Function to check IP address against VirusTotal and extract community score
async def check_ip_virustotal(ip, vt_client):
    try:
        vt_result = await vt_client.get_object_async(f"/ip_addresses/{ip}")
        # Extracting community score from the result
        if hasattr(vt_result, 'last_analysis_stats'):
            community_score = vt_result.last_analysis_stats['malicious']
            return community_score
        else:
            return None
    except vt.APIError as e:
        print(f"VirusTotal API Error: {e}")
    return None

async def check_dns_virustotal(dns, vt_client):
    try:
        vt_result = await vt_client.get_object_async(f"/domains/{dns}")
        if hasattr(vt_result, 'last_analysis_stats'):
            community_score = vt_result.last_analysis_stats['malicious']
            return community_score
        else:
            return None
    except vt.APIError as e:
        print(f"VirusTotal API Error: {e}")
    return None

# Iterate through unique destination IPs and check with VirusTotal
async def process_logs(vt_client, df):
    confirmed_mal_results = []
    sus_mal_results = []
    clean_results = []
    for ip in df['destination.ip'].unique():
        community_score = await check_ip_virustotal(ip, vt_client)
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
                
                dns_score = await check_dns_virustotal(dns, vt_client)
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
                dns_score = await check_dns_virustotal(dns, vt_client)
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
        print(f"User Name: {result['User Name']}")
        print(f"Host Name: {result['Host Name']}")
        if 'DNS' in result:
            print(f"DNS: {result['DNS']}")
            print(f"DNS Score: {result['DNS Score']}")
        print()


async def main():
    # Load Excel file into pandas dataframe
    excel_file = "C:/Users/prajs_28/OneDrive/Desktop/PKF ALgosmic/excel_logs/network_logs.xlsx"  # Replace with your actual Excel file name
    df = pd.read_excel(excel_file)
    vt_client = vt.Client("64d95710638db1d65f00a6e283175deca63f7ad4b9b7aafc47fedc0a30ccf827")
    await process_logs(vt_client, df)
    await vt_client.close_async()

if __name__ == "__main__":
    asyncio.run(main())
