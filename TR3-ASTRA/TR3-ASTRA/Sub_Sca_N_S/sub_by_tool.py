#!/usr/bin/env python3
import subprocess
import argparse
import os
import requests
from tabulate import tabulate

def logo():
    print("""
  ______             __              ______                              __    __         ______
 /      \           /  |            /      \                            /  \  /  |       /      \
/$$$$$$  | __    __ $$ |____       /$$$$$$  |  _______   ______         $$  \ $$ |      /$$$$$$  |
$$ \__$$/ /  |  /  |$$      \      $$ \__$$/  /       | /      \        $$$  \$$ |      $$ \__$$/
$$      \ $$ |  $$ |$$$$$$$  |     $$      \ /$$$$$$$/  $$$$$$  |       $$$$  $$ |      $$      \
 $$$$$$  |$$ |  $$ |$$ |  $$ |      $$$$$$  |$$ |       /    $$ |       $$ $$ $$ |       $$$$$$  |
/  \__$$ |$$ \__$$ |$$ |__$$ |     /  \__$$ |$$ \_____ /$$$$$$$ |       $$ |$$$$ |      /  \__$$ |
$$    $$/ $$    $$/ $$    $$/______$$    $$/ $$       |$$    $$ |______ $$ | $$$ |______$$    $$/
 $$$$$$/   $$$$$$/  $$$$$$$//      |$$$$$$/   $$$$$$$/  $$$$$$$//      |$$/   $$//      |$$$$$$/
                            $$$$$$/                             $$$$$$/          $$$$$$/



                                            """  + """THE TRI-ASTRA TOOL
""")

def run_amass(domain, output_file):
    amass_cmd = f'amass enum -d {domain} -o {output_file}'
    subprocess.run(amass_cmd, shell=True)

def run_sublist3r(domain, output_file):
    sublist3r_cmd = f'sublist3r -d {domain} -o {output_file}'
    subprocess.run(sublist3r_cmd, shell=True)

def merge_results(output_file_amass, output_file_sublist3r, merged_output_file):
    with open(output_file_amass, 'r') as file_amass:
        amass_results = set(file_amass.read().splitlines())

    with open(output_file_sublist3r, 'r') as file_sublist3r:
        sublist3r_results = set(file_sublist3r.read().splitlines())

    merged_results = amass_results.union(sublist3r_results)

    with open(merged_output_file, 'w') as file_merged:
        file_merged.write('\n'.join(merged_results))

def check_subdomain_exists(subdomain):
    try:
        response = requests.get(f'http://{subdomain}', timeout=5)
        return response.status_code, True
    except requests.ConnectionError:
        return None, False

def display_results_as_table(subdomains):
    table_headers = ["Subdomain", "Exists", "Status Code"]
    table_data = []

    for subdomain in subdomains:
        status_code, exists = check_subdomain_exists(subdomain)
        if status_code is not None:
            table_data.append([subdomain, exists, status_code])

    print(tabulate(table_data, headers=table_headers, tablefmt="grid"))

def save_results_as_table(subdomains, output_file):
    table_headers = ["Subdomain", "Exists", "Status Code"]
    table_data = []

    for subdomain in subdomains:
        status_code, exists = check_subdomain_exists(subdomain)
        if status_code is not None:
            table_data.append([subdomain, exists, status_code])

    with open(output_file, 'w') as file_table:
        file_table.write(tabulate(table_data, headers=table_headers, tablefmt="grid"))

def get_user_input():
    domain = input("Enter the target domain: ")
    return domain

def display_help():
    print("""
Usage:
python3 subdomain_tool.py

Options:
  -h, --help       Display this help message.
""")

if __name__ == "__main__":
    display_help()
    domain = get_user_input()
    output_file_amass = f'{domain}_amass_results.txt'
    output_file_sublist3r = f'{domain}_sublist3r_results.txt'
    merged_output_file = f'{domain}_merged_results.txt'
    all_subdomains = set()
    logo()

    try:
        run_amass(domain, output_file_amass)
        with open(output_file_amass, 'r') as file_amass:
            amass_results = set(file_amass.read().splitlines())
            all_subdomains.update(amass_results)

        run_sublist3r(domain, output_file_sublist3r)
        with open(output_file_sublist3r, 'r') as file_sublist3r:
            sublist3r_results = set(file_sublist3r.read().splitlines())
            all_subdomains.update(sublist3r_results)

        merge_results(output_file_amass, output_file_sublist3r, merged_output_file)
        display_results_as_table(all_subdomains)
        save_results_as_table(all_subdomains, merged_output_file)
        print(f"\nMerged subdomains saved to {merged_output_file}")
    except Exception as e:
        print(f"An error occurred: {e}")
