import sys
import math
import requests
from threatresponse import ThreatResponse

def ask_for_scd_index(count):
    '''Ask the user for a SCD index
       Keep asking until they enter a valid SCD index
    '''
    def clear_input(message):
        sys.stdout.write('\x1b[1A')
        sys.stdout.write('\x1b[2K')
        sys.stdout.write(message)

    while True:
        try:
            reply = (input('Enter the index of the SCD List you would like to check: '))
            index = int(reply)
            if 0 < index <= count:
                return index-1
            clear_input(f'{reply} is not a valid index try again.\n')
        except ValueError:
            clear_input(f'{reply} is not a number.\n')

def confirm_continue(message):
    '''Ask the user if they want to continue
       Keep asking until the input starts with  'y', 'Y', 'n', or 'N'
    '''
    while True:
        reply = str(input(f'{message}')).lower().strip()
        if reply[:1] == 'y': # using [:1] instead of [0] prevents IndexError if the reply is empty
            return True
        if reply[:1] == 'n':
            return False

def split_list(list_to_split, max_size=20):
    '''Split a large list into a list of lists with a maximum size of 20 items
    This is used to lighten the load on the Threat Response API by limiting the
    number of itmes in a single query to 20 instead of potentially thousands
    '''
    return [list_to_split[i:i + max_size] for i in range(0, len(list_to_split), max_size)]

def get_scd_file_lists(amp_hostname, session):
    '''Query AMP for Endpoints for SCD Lists
    '''
    url = f'https://{amp_hostname}/v1/file_lists/simple_custom_detections'
    response = session.get(url)
    return response

def get_file_list_items(amp_hostname, session, file_lists_guid):
    '''Get File List items for a given SCD GUID
    Paginate through the results when there are more than 500 items returned
    '''
    def query_api(url):
        '''Query the AMP for Endpoints AMP for the provided URL
        Return the decoded JSON response
        '''
        response = session.get(url)
        response_json = response.json()
        return response_json

    def parse_response(response_json):
        '''Parse the AMP for Endpoints response
        Store the SCD List items in the response container
        '''
        items = response_json.get('data', {}).get('items', [])
        response_items.extend(items)

    # Set the page count to 1
    page_count = 1

    # Container to store the SCD List items
    response_items = []

    print(f'Getting Page: {page_count} of', end=' ')
    url = f'https://{amp_hostname}/v1/file_lists/{file_lists_guid}/files'

    # Query AMP for Endpoints for SCD List items and decode the JSON response
    response_json = query_api(url)

    # Name total and items_per_page from the response
    total = response_json.get('metadata', {}).get('results', {}).get('total')
    items_per_page = response_json.get('metadata', {}).get('results', {}).get('items_per_page')

    # Calculate total number of pages
    pages = math.ceil(total/items_per_page)
    print(pages)

    # Parse AMP for Endpoints response
    parse_response(response_json)

    # Get the next page of results if needed
    while 'next' in response_json['metadata']['links']:
        page_count += 1
        print(f'Getting Page: {page_count} of {pages}')
        next_url = response_json['metadata']['links']['next']

        # Query AMP for Endpoints for the next page of SCD List items
        response_json = query_api(next_url)

        # Parse AMP for Endpoints response
        parse_response(response_json)

    return response_items

def delete_list_item(amp_hostname, session, file_lists_guid, sha256):
    '''Remove SHA256 from SCD
    '''
    url = f'https://{amp_hostname}/v1/file_lists/{file_lists_guid}/files/{sha256}'
    response = session.delete(url)
    return response

def get_verdicts(client, payload):
    '''Query Threat Response for Verdicts of SHA256s
    '''
    response = client.enrich.deliberate.observables(payload)
    return response

def parse_verdicts(response, malicious_hashes):
    '''Parse the Threat Response response check the AMP File Reputation for malicious dispositions
    '''
    data = response.get('data', [])

    # Iterate over returned data from each module
    for module in data:
        module_type_id = module.get('module_type_id')

        # Look for the AMP File Reputation module type
        if module_type_id == '1898d0e8-45f7-550d-8ab5-915f064426dd':
            verdicts = module.get('data', []).get('verdicts', {})
            docs = verdicts.get('docs', [])

            # Iterate over documents returned by the AMP File Reputation module
            for doc in docs:
                disposition = doc.get('disposition')
                observable = doc.get('observable', {}).get('value')
                if disposition == 2:
                    malicious_hashes.append(observable)

def main():
    '''Main script logic
    '''

    # AMP for Endpoints API Credentials
    amp_client_id = 'a1b2c3d4e5f6g7h8i9j0'
    amp_client_password = 'a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6'
    amp_hostname = 'api.amp.cisco.com'

    # Instantiate AMP for Endpoints Session
    amp_session = requests.Session()
    amp_session.auth = (amp_client_id, amp_client_password)

    # Threat Response API Credentials
    tr_client_id = 'client-asdf12-34as-df12-34as-df1234asdf12'
    tr_client_password = 'asdf1234asdf1234asdf1234asdf1234asdf1234asdf1234asdf12'

    # Instantiate Threat Response Client
    client = ThreatResponse(
        client_id=tr_client_id,
        client_password=tr_client_password,
    )

    # Container to store SHA256s that have malicious disposition in AMP cloud
    malicious_hashes = []

    # Get Simple Custom Detaction File Lists
    scd_lists = get_scd_file_lists(amp_hostname, amp_session).json()
    data = scd_lists.get('data', [])

    # Present SCD Lists to user and ask which one to process
    for index, scd in enumerate(data, start=1):
        print(f'{index} - {scd["name"]}')
    index = ask_for_scd_index(len(data))

    # Name SCD Name and GUID
    scd_name = data[index]['name']
    scd_guid = data[index]['guid']

    # Get List items for selected SCD List
    print(f'Getting items for: {scd_name}')
    scd_list_items = get_file_list_items(amp_hostname, amp_session, scd_guid)

    # Build Threat Response Enrich Payloads using list comprehension
    enrich_payloads = [
        {"value": list_item.get("sha256"), "type": "sha256"} for list_item in scd_list_items
    ]

    # Inform how many SCD List items were found
    print(f'{scd_name} has {len(enrich_payloads)} items')

    # Split payloads into list of lists with 20 items maximum
    chunked_enrich_payloads = split_list(enrich_payloads)

    # Iterate over list and get Verdicts for list of SCD List items
    for payload_index, payload in enumerate(chunked_enrich_payloads, start=1):

        # Query Threat Response for verdcits
        print(f'Checking verdicts for chunk {payload_index} of {len(chunked_enrich_payloads)}')
        verdicts = get_verdicts(client, payload)
        parse_verdicts(verdicts, malicious_hashes)

    # Inform how many malicious dispositions were returned
    print(f'Number of SHA256s on {scd_name} with a malicious disposition: {len(malicious_hashes)}')

    # Verify there are SHA256s with malicious dispositions and confirm the user wants to delete them
    if malicious_hashes:
        if not confirm_continue(
                f"Are you sure you want to remove these SHA256s from {scd_name}? (y/n): "
        ):
            sys.exit("Bye!")
    else:
        sys.exit()

    # Delete SHA256s with malicious disposition from selected SCD List
    for sha256 in malicious_hashes:
        print(f'Deleting {sha256}', end=' ')
        response = delete_list_item(amp_hostname, amp_session, scd_guid, sha256)
        if response.ok:
            print('- DONE!')
        else:
            print('- SOMETHING WENT WRONG!')

if __name__ == '__main__':
    main()
