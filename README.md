[![Gitter chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/AMP-for-Endpoints "Gitter chat")

### AMP for Endpoints Cleanup Simple Customer Detection Lists:

Script prompts the user for which SCD List they would like to clean up. Once chosen, it collects all of the items on the list (using pagination if needed) and then queries Threat Response for the current disposition of the file in the AMP File Reputation database. If the file has a `Malicious` disposition it is removed from the SCD List.

### Before using you must update the following:
- amp_client_id 
- amp_client_password
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
Enter the index of the SCD List you would like to check: 1
Getting items for: Simple Custom Detection List
Getting Page: 1 of 1
Simple Custom Detection List has 3 items
Checking verdicts for chunk 1 of 1
Number of SHA256s on Simple Custom Detection List with a malicious disposition: 2
Are you sure you want to remove these SHA256s from Simple Custom Detection List? (y/n): y
Deleting ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa - DONE!
Deleting 027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745 - DONE!
```
