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
            data_dict[ptype] = df0.applymap(remove_illegal_chars)
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

    result = result.loc[:, ~result.columns.duplicated()]

    column_names = result.columns.tolist()

    # value_n_result = column_names[11:] # Original line, kept for context
    # ip_list = [ip_addr, ''] # Original ip_list, seems insufficient for 3 columns per host

    # Part b: Correct the name_list generation for the second header row.
    name_list = []
    # num_hosts calculation for name_list
    # For a single host, columns beyond the first 11 base columns should be 'Actual Value', 'Result', 'Note'.
    # This calculation assumes each host adds exactly 3 columns.
    num_additional_columns = len(column_names) - 11
    num_hosts = 0
    if num_additional_columns >= 0 and num_additional_columns % 3 == 0:
        num_hosts = num_additional_columns // 3

    for _ in range(num_hosts):
        name_list.extend(['Actual Value', 'Result', 'Note'])

    # Part a: Correct the problematic column assignment.
    base_columns = ['Checklist', 'Type', 'Index', 'Description', 'Solution', 'Reg Key', 'Reg Item', 'Reg Option', 'Audit Policy Subcategory', 'Right type', 'Value Data']
    # actual_df_column_names are the final column names for the DataFrame *data* rows
    actual_df_column_names = base_columns + name_list # name_list now correctly holds all per-host column names like ['Actual Value', 'Result', 'Note', 'Actual Value_H2', ...]
                                                    # However, the original script structure implies a single host's data is processed by save_file,
                                                    # based on `ip_addr` parameter and how `results.append(new_dict)` is done.
                                                    # If `results` (and thus `result` after concat) truly only has one host's data,
                                                    # then num_hosts will be 1, and name_list will be ['Actual Value', 'Result', 'Note'].
                                                    # This makes actual_df_column_names have 11 + 3 = 14 columns.

    if len(result.columns) == len(actual_df_column_names):
        result.columns = actual_df_column_names
    else:
        print(f"WARNING: Column count mismatch in save_file. DataFrame has {len(result.columns)} columns but expected {len(actual_df_column_names)}. Column names not reassigned before creating Excel header rows.")
        # Fallback or error handling might be needed if this warning is triggered.
        # For now, we proceed, but the header generation might be misaligned if this happens.

    # new_data is for the content of the *second* header row in Excel.
    # It should align with the final DataFrame column structure.
    new_data_header_row_content = base_columns + name_list

    # The new_df is used to write the two header rows. Its columns must match `result.columns` after the potential reassignment.
    # If result.columns was not reassigned due to mismatch, this new_df might also be misaligned.
    # We will use actual_df_column_names for new_df's columns if the assignment to result.columns happened,
    # otherwise, we use the original result.columns to avoid crashing here, though Excel output might be wrong.
    header_for_new_df = actual_df_column_names if len(result.columns) == len(actual_df_column_names) else result.columns.tolist()

    new_df = pd.DataFrame(
        [new_data_header_row_content + [''] * (len(header_for_new_df) - len(new_data_header_row_content))], columns=header_for_new_df)
    result = pd.concat([new_df, result]).reset_index(drop=True)

    # Apply the function to each string column in the DataFrame
    result = result.applymap(remove_illegal_chars)

    # Save DataFrame to a new Excel file
    result.to_excel(out_fname, index=False)

    # Load the workbook and select the sheet
    wb = load_workbook(out_fname)
    ws = wb.active

    # Merge the appropriate cells in the new first row
    for col_idx_excel in range(1, 12):  # For base columns (A to K)
        ws.merge_cells(start_row=1, start_column=col_idx_excel,
                       end_row=2, end_column=col_idx_excel)

    # Part c: Correct the openpyxl merge logic for the first header row (IP address / Hostname).
    num_base_columns_excel = 11 # Number of base columns (A-K)

    # num_hosts was calculated earlier for name_list. This is based on the structure of `result` DataFrame.
    # This calculation assumes `result` has 11 base columns + 3 columns per host.

    for i in range(num_hosts):
        start_col_for_host_excel = num_base_columns_excel + (i * 3) + 1 # 1-based index for openpyxl

        # The actual IP/hostname should have been written by new_df.to_excel() into ws.cell(row=1, column=start_col_for_host_excel).
        # Here, we just merge the cells for that host header.
        # The first row of new_df (which becomes the first row in Excel) should have the ip_addr for the first host block.
        # The original script only passed a single `ip_addr`. If multiple hosts were processed into `result`,
        # the `new_df` construction would need ip_addr for each host block.
        # The current logic writes `ip_addr` (passed to save_file) for the first host block.
        # Subsequent host blocks in a multi-host scenario are not explicitly given unique IP headers by current new_df logic.
        # This merge logic assumes 3 columns per host ('Actual Value', 'Result', 'Note').

        # Ensure we don't try to merge beyond available columns
        end_col_for_host_excel = start_col_for_host_excel + 2
        if start_col_for_host_excel <= ws.max_column:
            # If end_col_for_host_excel goes beyond max_column, merge only up to max_column
            actual_end_col = min(end_col_for_host_excel, ws.max_column)
            ws.merge_cells(start_row=1, start_column=start_col_for_host_excel, end_row=1, end_column=actual_end_col)

    # Save the workbook
    wb.save(out_fname)
    print((f"Result saved into {out_fname}"))

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
