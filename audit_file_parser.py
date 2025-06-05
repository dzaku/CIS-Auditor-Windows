from bs4 import BeautifulSoup
import pandas as pd
import re
import argparse
import sys
import os

# The regular expressions to extract required data
regexes = {
    'type': re.compile(r'type\s+:\s+(.*?)\n'),
    'description': re.compile(r'description\s+:\s+(.*?)\n'),
    'value_data': re.compile(r'value_data\s+:\s+(.*?)\n'),
    'reg_key': re.compile(r'reg_key\s+:\s+(.*?)\n'),
    'reg_item': re.compile(r'reg_item\s+:\s+(.*?)\n'),
    'reg_option': re.compile(r'reg_option\s+:\s+(.*?)\n'),
    'audit_policy_subcategory': re.compile(r'audit_policy_subcategory\s+:\s+(.*?)\n'),
    'key_item': re.compile(r'key_item\s+:\s+(.*?)\n'),
    'right_type': re.compile(r'right_type\s+:\s+(.*?)\n'),
    'guid_reg_key': re.compile(r'guid_reg_key\s+:\s+(.*?)\n'), # Extracts GUID-based registry keys, typically used in v3 CIS audit files
    # 'solution': re.compile(r'solution\s*:\s*(.+?)\n\s*Default Value:', re.DOTALL | re.IGNORECASE)
    'solution': re.compile(r'solution\s*:\s*(.+?)\n\s*reference', re.DOTALL | re.IGNORECASE)
}


# The dictionary maps different audit categories
data_dict = {
    "PASSWORD_POLICY": [],
    "REGISTRY_SETTING": [],
    "LOCKOUT_POLICY": [],
    "USER_RIGHTS_POLICY": [],
    "CHECK_ACCOUNT": [],
    "BANNER_CHECK": [],
    "ANONYMOUS_SID_SETTING": [],
    "AUDIT_POLICY_SUBCATEGORY": [],
    "REG_CHECK": [],
    "WMI_POLICY": [],
    "SERVICE_POLICY": [],
    "GUID_REGISTRY_SETTING": [] # Stores items related to GUID-based registry settings, common in v3 CIS benchmarks
}


def read_file(filename: str) -> str:
    '''
    Reads the contents of a file and returns it as a string.

    :param filename: The path to the file to read.
    :return: A string containing the contents of the file.
    '''

    contents = ''
    try:
        with open(filename, 'r') as file_in:
            contents = file_in.read()
    except Exception as e:
        print('ERROR: reading file: {}: {}'.format(filename, e))

    return contents


def find_element(audit: str) -> None:
    '''
    Processes an audit string, extracts relevant information according to predefined regular expressions, 
    and stores the results in a global dictionary.

    :param audit: The audit string to process.
    :return: None
    '''

    soup = BeautifulSoup(audit, 'lxml')

    # Find all the custom_item elements
    items = soup.find_all('custom_item')

    # Extract the required data from each custom_item
    for item in items:
        item_str = str(item)
        # item_str = str(item).replace('"', '')

        type = regexes['type'].search(item_str)
        type = type.group(1) if type else None

        if type == "AUDIT_POWERSHELL":
            continue
        else:
            type = type.strip()

        description = regexes['description'].search(item_str)
        description = description.group(1) if description else None
        description = description.replace('"', '')

        if description[0].isdigit():
            index = re.search(r'(.*?)\s', description)
            index = index.group(1) if index else None
            description = description.replace(index, '').strip()
        else:
            index = 0

        index = str(index).strip()

        solution = regexes['solution'].search(item_str)
        solution = solution.group(1).strip('"').replace(
            '\n', ' ') if solution else None

        value_data = regexes['value_data'].search(item_str)
        value_data = value_data.group(1) if value_data else None
        value_data = str(value_data).replace('"', '')
        value_data = str(value_data).replace('&amp;&amp;', '&&')

        reg_key = regexes['reg_key'].search(item_str)
        reg_key = (reg_key.group(1)).replace('"', '') if reg_key else None

        reg_item = regexes['reg_item'].search(item_str)
        reg_item = (reg_item.group(1)).replace('"', '') if reg_item else None

        reg_option = regexes['reg_option'].search(item_str)
        reg_option = (reg_option.group(1)).replace(
            '"', '') if reg_option else None

        key_item = regexes['key_item'].search(item_str)
        key_item = key_item.group(1) if key_item else None

        if key_item:
            reg_item = key_item.replace('"', '')

        audit_policy_subcategory = regexes['audit_policy_subcategory'].search(
            item_str)
        audit_policy_subcategory = (audit_policy_subcategory.group(
            1)).replace('"', '') if audit_policy_subcategory else None

        right_type = regexes['right_type'].search(item_str)
        right_type = (right_type.group(1)).replace(
            '"', '') if right_type else None

        # Extract GUID-based registry key if present
        guid_reg_key = regexes['guid_reg_key'].search(item_str)
        guid_reg_key = (guid_reg_key.group(1)).replace('"', '') if guid_reg_key else None

        # Clean the data
        if type == 'BANNER_CHECK':
            value_data = ''
        elif type == 'ANONYMOUS_SID_SETTING':
            value_data = '0'
        elif type == 'REG_CHECK':
            reg_key = value_data
            value_data = ''
        elif type == 'CHECK_ACCOUNT':
            if 'Rename administrator account' in description:
                value_data = 'Administrator'
            elif 'Disabled' in description:
                value_data = 'No'
        elif type == 'PASSWORD_POLICY':
            if value_data == 'Enabled':
                value_data = 1
            elif value_data == 'Disabled':
                value_data = 0
            elif value_data == '@PASSWORD_HISTORY@':
                value_data = 24
            elif value_data == '@MAXIMUM_PASSWORD_AGE@':
                value_data = 365
            elif value_data == '@MINIMUM_PASSWORD_AGE@':
                value_data = 1
            elif value_data == '@MINIMUM_PASSWORD_LENGTH@':
                value_data = 14
        elif type == 'REGISTRY_SETTING':
            if index == '0':
                value_data = 'Windows'
            elif 'Lock Workstation' in description:
                value_data = '1 || 2 || 3'
            elif 'None' in description:
                value_data = 'Null'
            elif ' Remotely accessible registry paths' in description:
                value_data = value_data.replace(' && ', '')
            elif 'Screen saver timeout' in description:
                value_data = '[0..900]'

        data_dict[type].append([1, type, index, description, solution,
                                reg_key, reg_item, reg_option, audit_policy_subcategory, right_type, value_data, guid_reg_key])


def output_file(out_fname):
    '''
    Saves the global data dictionary to an Excel file.

    :param out_fname: The path where the output Excel file will be saved.
    :return: None
    '''

    writer = pd.ExcelWriter(out_fname, engine='openpyxl')

    for type, data in data_dict.items():
        df = pd.DataFrame(data, columns=['Checklist', 'Type', 'Index', 'Description', 'Solution',
                                         'Reg Key',  'Reg Item', 'Reg Option', 'Audit Policy Subcategory', 'Right type', 'Value Data', 'GUID Reg Key'])
        df.to_excel(writer, sheet_name=type, index=False)

    writer.close()


'''
Parses command-line arguments for an audit file, processes the audit file, and saves the results to an Excel file.

:return: None
'''
if __name__ == '__main__':

    my_parser = argparse.ArgumentParser(
        description='This script parses CIS audit files (supports v2 and v3) and generates an Excel file. It extracts various policy settings, including GUID-based registry settings common in v3 benchmarks.')

    # Add the arguments
    my_parser.add_argument('-audit',
                           type=str,
                           required=True,
                           help='(REQUIRED) The path to the raw audit file. This should be a .audit file.')

    # Execute parse_args()
    try:
        args = my_parser.parse_args()
    except SystemExit:
        my_parser.print_help()
        sys.exit(1)

    print('Aduit file:', args.audit)

    # src_fname = 'src/CIS/CIS_MS_Windows_11_Enterprise_Level_1_v1.0.0.audit'
    # src_fname = 'src/CIS/CIS_Microsoft_Windows_Server_2019_Benchmark_v2.0.0_L1_DC.audit'
    src_fname = args.audit

    # read .audit file
    audit = read_file(src_fname)

    # extract the required audit data
    data = find_element(audit)

    # save the data into an Excel file
    # Construct the output filename by taking the base name of the audit file,
    # placing it in the 'src/Audit/' directory, and changing the extension to .xlsx.
    # e.g., src/CIS/file.audit -> src/Audit/file.xlsx
    base_name = os.path.basename(src_fname)
    out_fname = os.path.join('src', 'Audit', base_name.replace("audit", "xlsx"))

    output_file(out_fname)

    print(f"File export success --- {out_fname}")
