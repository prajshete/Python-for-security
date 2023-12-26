import re
import requests
import subprocess
from collections import Counter
import time

def get_failed_logins(log_file):
    with open(log_file, 'r') as auth_log:
        log_content = auth_log.read()
        failed_logins = re.findall(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)', log_content)
    return failed_logins

def add_to_blacklist(ip, blacklist_file):
    with open(blacklist_file, 'a') as blacklist:
        blacklist.write(ip + '\n')

def check_reputation(ip, api_key):
    url = f'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey': api_key, 'ip': ip}
    response = requests.get(url, params=params)
    result = response.json()
    if 'positives' in result:
        return result['positives']
    return None

def main():
    auth_log_file = '/var/log/auth.log'
    blacklist_file = 'blacklist.txt'
    virus_total_api_key = 'paste the api key here'

    while True:
        failed_logins = get_failed_logins(auth_log_file)
        
        for ip, count in Counter(failed_logins).items():
            if count > 2:
                print(f'IP {ip} failed login attempts: {count}')
                add_to_blacklist(ip, blacklist_file)
                reputation_score = check_reputation(ip, virus_total_api_key)
                if reputation_score is not None:
                    print(f'VirusTotal Reputation Score for {ip}: {reputation_score}')

        time.sleep(60)  # Sleep for 60 seconds before checking again

if __name__ == '__main__':
    main()
