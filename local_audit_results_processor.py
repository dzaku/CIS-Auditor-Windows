import pandas as pd
import time
import logging
import argparse
import sys

from openpyxl import load_workbook

from utilities.getPwdPolicy import compare_pwd_policy_local
from utilities.getRegValue import compare_reg_value_local
from utilities.getLockoutPolicy import compare_lockout_policy_local
from utilities.getUserRights import compare_user_rights_local
from utilities.getCheckAccount import compare_check_account_local
from utilities.getBannerCheck import compare_banner_check_local
from utilities.getAnonySID import compare_anonymous_sid_local
from utilities.getAuditPolicy import compare_audit_policy_local
from utilities.getRegCheck import compare_reg_check_local
from utilities.getWMIPolicy import compare_wmi_policy_local


def get_actual_values(data_dict: dict) -> dict:
    '''
    This function takes a dictionary of data as input. For each type of audit, 
    it calls the appropriate function to compare the actual and expected values. 
    The function then returns a new dictionary with the comparison results.

    :param data_dict: 
        A dictionary with keys representing different audit types and values as 
        DataFrames containing the audit data.
    :return: 
        A new dictionary with the same keys as data_dict but the values replaced 
        with DataFrames that include the results of the comparison between the 
        actual and expected values.
    '''

    new_dict = {}

    for key in data_dict.keys():

        try:

            if key == "PASSWORD_POLICY":
                new_df = compare_pwd_policy_local(data_dict)
            elif key == "REGISTRY_SETTING":
                new_df = compare_reg_value_local(data_dict)
            elif key == "LOCKOUT_POLICY":
                new_df = compare_lockout_policy_local(data_dict)
            elif key == "USER_RIGHTS_POLICY":
                new_df = compare_user_rights_local(data_dict)
            elif key == "CHECK_ACCOUNT":
                new_df = compare_check_account_local(data_dict)
            elif key == "BANNER_CHECK":
                new_df = compare_banner_check_local(data_dict)
            elif key == "ANONYMOUS_SID_SETTING":
                new_df = compare_anonymous_sid_local(data_dict)
            elif key == "AUDIT_POLICY_SUBCATEGORY":
                new_df = compare_audit_policy_local(data_dict)
            elif key == "REG_CHECK":
                new_df = compare_reg_check_local(data_dict)
            elif key == "WMI_POLICY":
                new_df = compare_wmi_policy_local(data_dict)

            new_dict[key] = new_df
        except Exception as e:
            print('Failed to get actual value:', e)

    return new_dict


def read_file(fname: str) -> dict:
    '''
    This function reads the provided audit file and returns a dictionary where 
    the keys are different audit types and the values are corresponding audit 
    data in DataFrame format.

    :param fname: 
        A string representing the filename of the audit file.
    :return: 
        A dictionary with keys representing different audit types and values as 
        DataFrames containing the audit data.
    '''

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
        "WMI_POLICY": []
    }

    xl = pd.ExcelFile(fname)
    # df = xl.parse(sheet_name=0)

    for ptype in data_dict:
        try:
            df0 = xl.parse(sheet_name=ptype)
            data_dict[ptype] = df0.map(remove_illegal_chars)
        except ValueError as e:
            logging.error(f"{ptype} not found")

    return data_dict


def remove_illegal_chars(val: str) -> str:
    '''
    This function checks if the given value is a string, and if so, removes any 
    non-printable characters.

    :param val: 
        A string potentially containing non-printable characters.
    :return: 
        The same string but with any non-printable characters removed.
    '''

    if isinstance(val, str):
        # Remove control characters
        val = ''.join(ch for ch in val if ch.isprintable())
    return val


def save_file(out_fname: str, data_dict_list: list, ip_addr: str) -> None:
    '''
    This function processes the comparison results and saves them into an Excel file.
    It now writes the main data first using pandas.ExcelWriter, starting from Excel row 3,
    and then uses openpyxl to manually write the two header rows and apply merges.

    :param out_fname: 
        A string representing the filename of the output file.
    :param data_dict_list: 
        A list of dictionaries containing comparison results.
    :param ip_addr: 
        A string representing an IP address.
    :return: 
        None
    '''

    if data_dict_list == []:
        return

    all_frames = []

    for data_dict in data_dict_list:
        frames = []

        for df in data_dict.values():
            frames.append(df)
        result_rowwise = pd.concat(frames)
        all_frames.append(result_rowwise.reset_index(drop=True))

    result = pd.concat(all_frames, axis=1)

    result = result.loc[:, ~result.columns.duplicated()] # Keep this, seems useful

    # 1. Apply `remove_illegal_chars` carefully
    for col in result.columns:
        if result[col].dtype == 'object':
            result[col] = result[col].map(remove_illegal_chars, na_action='ignore')

    # 2. Use `pandas.ExcelWriter` to write the data *without* pandas headers,
    # starting from row 3 (Excel's 1-based indexing for startrow=2).
    with pd.ExcelWriter(out_fname, engine='openpyxl') as writer:
        result.to_excel(writer, index=False, header=False, sheet_name='Sheet1', startrow=2)

    # 3. Subsequent `openpyxl` logic for loading the workbook,
    # writing the two header rows, and merging cells.
    wb = load_workbook(out_fname)
    ws = wb.active # Should be 'Sheet1'

    # Define base column names (literal list)
    base_column_names_literal = ['Checklist', 'Type', 'Index', 'Description', 'Solution', 'Reg Key', 'Reg Item', 'Reg Option', 'Audit Policy Subcategory', 'Right type', 'Value Data']

    # Calculate num_hosts based on the 'result' DataFrame's columns (before it was written to Excel)
    # This DataFrame `result` is the one containing only data, no headers yet.
    num_base_cols = 11
    num_result_cols_per_host = 3 # 'Actual Value', 'Result', 'Note'
    num_hosts = 0
    # Check if the number of additional columns is non-negative and a multiple of per-host columns
    if (len(result.columns) - num_base_cols) >= 0 and \
       (len(result.columns) - num_base_cols) % num_result_cols_per_host == 0:
        num_hosts = (len(result.columns) - num_base_cols) // num_result_cols_per_host
    else:
        # This case implies the DataFrame `result` doesn't match the expected structure
        # (11 base + 3*N host data columns).
        # This could happen if `data_dict_list` had items with varying structures,
        # or if `ip_addr` logic implies only one host but columns don't match.
        # For now, proceed with num_hosts = 0 or log a warning.
        # The current code for `all_frames.append(result_rowwise.reset_index(drop=True))` and
        # `result = pd.concat(all_frames, axis=1)` suggests `result` could combine multiple hosts
        # if `data_dict_list` had multiple items.
        # However, the `main` block calls `save_file` with `results = [new_dict]`, meaning `data_dict_list` has one item.
        # So, `result` should correspond to one host's data.
        # Let's assume for a single host scenario, result.columns should be 11 + 3 = 14.
        if len(result.columns) == num_base_cols + num_result_cols_per_host: # Exactly one host
             num_hosts = 1
        else:
            print(f"WARNING: Column structure of 'result' DataFrame ({len(result.columns)} columns) does not match expected 11 base + 3*N host columns. Header generation might be incorrect.")
            # If num_hosts remains 0, no host-specific headers will be written/merged.

    # Header Row 1 content (IPs / Hostnames for result columns)
    # For base columns, this row will effectively be empty where cells are merged vertically.
    # The actual text for base columns in row 1 comes from header_row2_content before merging.
    header_row1_excel_content = [''] * num_base_cols
    for i in range(num_hosts):
        # Assuming ip_addr is for the first host. If multiple hosts, this needs adjustment.
        current_ip_header = ip_addr if i == 0 else f"Host_{i+1}_IP_Placeholder"
        header_row1_excel_content.extend([current_ip_header, '', '']) # IP spans 3 cells

    # Header Row 2 content (Actual column titles)
    header_row2_excel_content = list(base_column_names_literal) # Make a mutable copy
    for _ in range(num_hosts):
        header_row2_excel_content.extend(['Actual Value', 'Result', 'Note'])

    # Write Header Row 1 cells (content for this row)
    for col_idx, cell_value in enumerate(header_row1_excel_content):
        # For base columns, the visual text in row 1 will be the base_column_name after merge.
        # So, write the base_column_name into row 1 for base columns.
        if col_idx < num_base_cols:
            ws.cell(row=1, column=col_idx + 1, value=base_column_names_literal[col_idx])
        else: # For host-specific columns, write the IP/host identifier.
            ws.cell(row=1, column=col_idx + 1, value=cell_value)

    # Write Header Row 2 cells (content for this row)
    for col_idx, cell_value in enumerate(header_row2_excel_content):
         ws.cell(row=2, column=col_idx + 1, value=cell_value)

    # Perform merges for headers
    # Vertically merge cells for base column headers (A1:A2, B1:B2, ..., K1:K2)
    for col_idx_plus_1 in range(1, num_base_cols + 1):
        ws.merge_cells(start_row=1, start_column=col_idx_plus_1, end_row=2, end_column=col_idx_plus_1)

    # Horizontally merge cells for each host's IP/Hostname header (e.g., L1:N1 for first host)
    for i in range(num_hosts):
        start_col_for_host_excel = num_base_cols + (i * num_result_cols_per_host) + 1
        end_col_for_host_excel = start_col_for_host_excel + num_result_cols_per_host - 1

        if start_col_for_host_excel <= ws.max_column: # Ensure start column is valid
            # Adjust end_col if it exceeds current max_column (though ws.max_column might be based on data written)
            # It's safer to merge based on calculated end_col_for_host_excel, assuming data columns exist
            actual_end_col = min(end_col_for_host_excel, len(header_row1_excel_content)) # Max theoretical columns based on headers
            if actual_end_col >= start_col_for_host_excel :
                 ws.merge_cells(start_row=1, start_column=start_col_for_host_excel, end_row=1, end_column=actual_end_col)

    # Save the workbook with new headers
    wb.save(out_fname)
    print(f"Result saved into {out_fname}")
    logging.info(f"Result saved into {out_fname}")


'''
This is the main function that gets executed when the script runs. It parses 
command-line arguments, reads the audit file, compares actual and expected 
values for each audit type, and finally saves the comparison results into an 
output file.
'''
if __name__ == '__main__':

    my_parser = argparse.ArgumentParser(
        description="This is a script for processing audit results.")

    # Add the arguments
    my_parser.add_argument('-ps_result',
                           type=str,
                           required=True,
                           help='(REQUIRED) The path of the result file generated after running the PowerShell script. This should be a .txt file.')

    my_parser.add_argument('-output',
                           type=str,
                           required=True,
                           help='(REQUIRED) The path where the output result file should be saved. This should be a .txt file.')

    my_parser.add_argument('-audit',
                           type=str,
                           required=True,
                           help='(REQUIRED) The path of the parsed audit file that contains the audit results you want to process. This should be a .xlsx file')

    # Execute parse_args()
    try:
        args = my_parser.parse_args()
    except SystemExit:
        my_parser.print_help()
        sys.exit(1)

    print('PowerShell result file:', args.ps_result)
    print('Output file:', args.output)
    print('Audit file:', args.audit)

    start_t0 = time.time()

    # result_fname = "output_win10.txt"
    result_fname = args.ps_result

    output_list = []
    with open(result_fname, 'r', encoding='utf-16') as file:
        lines = file.readlines()

    single_line = ' '.join(line.strip() for line in lines)

    # actual value list
    output_list = single_line.strip().split("====")
    output_list.pop(0)
    ip_addr = output_list[0]
    output_list.pop(0)

    # audit_fname = "src\Audit\CIS_MS_Windows_10_Enterprise_Level_1_v2.0.0.xlsx"
    audit_fname = args.audit

    data_dict = read_file(audit_fname)

    # add actual value to the audit file
    head = 0
    for key in data_dict:
        length = len(data_dict[key])
        data_dict[key]['Actual Value'] = output_list[head: (head+length)]
        head += length

    # print(data_dict)

    new_dict = get_actual_values(data_dict)
    results = []
    results.append(new_dict)

    # # write output file
    save_file(args.output, results, ip_addr)
