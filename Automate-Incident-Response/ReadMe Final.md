
# **Automate Incident Response using ELK SIEM**


### Execution

- Open CMD in the folder
- Run
```bash
python3 initiate_IR.py --timestamp "enter time range here for e.g. 24h, 48h ..."

eg

python3 initiate_IR.py --timestamp 24h

```
### Changes to be made

- provide API keys, passowords, elastic instance
- assign paths to directories
- uncomment isolate() in response() when in actual production


### Workflow

1. The program first reads the false positives lookup file.
2. Based on these false positive it creates a search query to be executed.
3. it connects to Elastic Instance using host URL and API key.
4. Executes the search query and stores the logs.
5. The logs are then processed (relevant fields, remove duplicates) and passed to VirusTotal for processing, where each log entry is searched for reputation hits.
6. The new logs are stored in output directory with an additional column of 'Type' by tagging each log as 'Confirmed Malicious' 'Suspicious' 'Clean'
7. Response process is then initiated
8. Compromised Hosts are isolated.
9. Relevant context logs like all HTTP/DNS connections, File Executions, Sign-in logs are captured and stored for each user.
10. Virustotal Log files, Compromised logs are zipped and an email alert is sent with these attachments.

### Code Functionalities

read_api_key( ) and get_vt_api_key( )

- Reads API key from the files and assigns it into the code

read_false_positive_domains( )

- Returns all the domains listed in the look-up file which will help to build a elastic search query

build_elasticsearch_query_http( ) and build_elasticsearch_query_dns( )

- Builds a search query using the returned domains

get_dns_network_logs( ) and get_http_network_logs( )

- Retrieves logs from ELK

check_ip_virustotal( ) and check_dns_virustotal( )

- gets results from VirusTotal

process_logs_http( ) and process_logs_dns( )

- processes logs retrieved from Virurstotal (remove duplicates, add tags and stores results)

send_email( )

- sends email alert with relevant log files as the attachment

capture_context_logs( )

- calls get_compromised_http_dns_logs( ), get_signin_logs( ) and get_file_download_logs( )

- gets context logs for each user and stores it into seperate directories for every user

initiate_host_isolation( )

- get_endpoint_id( ) : retrieves endpoind id required to isolate the specific host
- isolate_host( ) : Isolates host based on retrieved endpoint id.

colorfill( )

- assigns color to each row in the log based upon the tag.
- Red for Malicious, Yellow for Suspicious, Green for clean


