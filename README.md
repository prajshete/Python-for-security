# Python-for-security
The repo includes programs that automate tasks in security domain

1. IOC Generator
  - Automate extraction of file signatures like file properties, hashes, API calls, loaded libraries, IP address/FQDN’s/URL’s in the form of C2.
  - Used regex as the methodology for IP addresses and domains
    
3. Integrity Checker
  - Developed an automated file hash checker which will execute at regular intervals to check for modifications made in any directory.
  - Created a json file with file hashes stored for each file in the directory which acts as a baseline.
  - Monitors the directory after every 60 seconds for modification (change in hash, hence change in baseline)
  - Provides an alert with file path if any modifications are found.
