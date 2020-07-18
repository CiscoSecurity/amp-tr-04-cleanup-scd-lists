[![Gitter chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/AMP-for-Endpoints "Gitter chat")

### AMP for Endpoints Cleanup Simple Customer Detection Lists:

Script prompts the user for which SCD List they would like to clean up. Once chosen, it collects all of the items on the list (using pagination if needed) and then queries Threat Response for the current disposition of the file in the AMP File Reputation database. If the file has a `Malicious` disposition it is saved to a file and the user is asked if they would like to remove the SHA256s from the SCD List.

The script saves the SHA256s that have a `Malicious` disposition to a file with the following name:  
`<SCD NAME>_<SCD GUID>_<DATE TIMESTAMP>.txt`

### Before using you must update the following:
- amp_client_id
- amp_client_password
- amp_hostname
- tr_client_id
- tr_client_password

Install required Python modules using:
```
pip install -U -r requirements.txt
```

### Usage:
```
python cleanup_scd.py
```

### Example script output:  
```
1 - Simple Custom Detection List
2 - PDFs
3 - Binaries
Enter the index of the SCD List you would like to check: 3

Getting SHA256s for: Binaries
  Page: 1 of 1
SHA256s on Binaries: 37

Splitting into 2 chunks of 20 or less and checking verdicts
  Checking verdicts for chunk 1 of 2
  Checking verdicts for chunk 2 of 2
Number of SHA256s on Binaries with a malicious disposition: 2

Saving SHA256s to file:
  Binaries_77515783-2ed0-4796-b8d4-acf7ab673578_2020-07-18T18.58.55.164440.txt

Do you want to remove these SHA256s from Binaries? (y/n): y
Deleting ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa - DONE!
Deleting 027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745 - DONE!
```
