#!/usr/bin/env python3
# -----------------------------------------------------------------------
# A small python script to scrape the public pastebin archive.
# Copyright (C) 2019  Mili
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------

import sys
import lib
import json
import yara
import codecs
from time import sleep
from bs4 import BeautifulSoup
from sys import path as syspath
from os import path, listdir

# Author: Mili
# No API key needed

# Setup Function:
def config(configpath):
    """
    :param configpath: path to config file, if it is blank or non-existent, it runs manual setup
    :return: vars_dict, a dictionary containing all the variables needed to run the main functions
    """
    # Manual Setup:
    if path.isfile(configpath) is False:
        # Save Path Input:
        while True:
            workpath = lib.print_input(
                "Enter the path you wish to save text documents to (enter curdir for current directory)")
            workpath = syspath[0] if workpath.lower() == 'curdir' else workpath
            if path.isdir(workpath):
                lib.print_success("Valid Path...")
                workpath = workpath if any([workpath.endswith('\\'), workpath.endswith('/')]) else f'{workpath}/'
                break
            else:
                lib.print_error("Invalid path, check input...")
                continue
        # Looping, Limiter, and Cooldown Input:
        while True:
            try:
                loop_input = lib.print_input("Run in a constant loop? [y]/[n]")
                if loop_input.lower() == 'y':
                    stop_input = True
                elif loop_input.lower() == 'n':
                    stop_input = int(
                        lib.print_input("Enter the amount of individual pastes to fetch: "))
                    # If they enter 0 or below pastes to fetch, run in an infinite loop:
                    stop_input = True if stop_input <= 0 else stop_input
                # Limiter and Cooldown
                limiter = int(lib.print_input("Enter the request limit you wish to use (recommended: 5)"))
                cooldown = int(
                    lib.print_input("Enter the cooldown between IP bans/Archive scrapes (recommended: 1200)"))
                # If no values are entered, select the recommended
                limiter = 5 if limiter == "" else limiter
                cooldown = 1200 if cooldown == "" else cooldown
                break
            except ValueError:
                lib.print_error("Invalid Input.")
                continue
        # YARA
        while True:
            yara_choice = lib.print_input("Enable scanning documents using YARA rules? [y/n]")
            if yara_choice.lower() not in ['y', 'n', 'yes', 'no']:
                lib.print_error("Invalid Input.")
                continue
            elif yara_choice.lower() in ['y', 'yes']:
                yara_scanning = True
            elif yara_choice.lower() in ['n', 'no']:
                yara_scanning = False
            break
        # Building Settings Dict:
        vars_dict = {
            'workpath': workpath,
            'stop_input': stop_input,
            'limiter': limiter,
            'cooldown': cooldown,
            'yara_scanning': yara_scanning
        }
        # Saving
        savechoice = lib.print_input('Save configuration to file for repeated use? [y]/[n]')
        if savechoice.lower() == 'y':
            configname = lib.print_input("Enter the config name (no extension)")
            configname = configname.split(".")[0] if '.json' in configname else configname
            json.dump(vars_dict, open(f"{configname}.json", 'w'))
    # Loading Config:
    else:
        vars_dict = json.load(open(configpath))
    # YARA Compilation:
    if vars_dict['yara_scanning']:
        vars_dict['search_rules'] = yara.compile(filepaths={f.split('.')[0]: path.join(f'{syspath[0]}/yara_rules/general_rules/', f) for f in listdir(f'{syspath[0]}/yara_rules/general_rules/') if path.isfile(path.join(f'{syspath[0]}/yara_rules/general_rules/', f)) and f.endswith(".yar") or f.endswith(".yara")})
        vars_dict['binary_rules'] = yara.compile(filepaths={f.split('.')[0]: path.join(f'{syspath[0]}/yara_rules/binary_rules/', f) for f in listdir(f'{syspath[0]}/yara_rules/binary_rules/') if path.isfile(path.join(f'{syspath[0]}/yara_rules/binary_rules/', f)) and f.endswith(".yar") or f.endswith(".yara")})
    # Display and Return:
    try:
        print("\n")
        for x in vars_dict.keys():
            if x != 'search_rules' and x != 'binary_rules':
                print(f"\x1b[94m[{x}]\x1b[0m: " + f"\x1b[1;32;40m{str(vars_dict[x])}\x1b[0m")
                print("\x1b[94m---------------------\x1b[0m")
    finally:
        print("\n")
        return vars_dict
# Matching and Saving Function:
def archive_engine(prescan_text, proch, vars_dict):
    """
    This function scans files for YARA matches (if enabled) and saves files.

    :param prescan_text: The raw text of the paste
    :param proch: The URL parameter of the paste (i.e: https://pastebin.com/{proch})
    :param vars_dict: dict of variables returned from config()
    :return: Nothing, saves files if they aren't blacklisted and if they are, does nothing
    """
    if vars_dict['yara_scanning'] is True:
        matches = vars_dict['search_rules'].match(data=prescan_text)
        # If there are matches, it saves them under different names
        if matches:
            components = {'rule': matches[0].rule,
                          # If term is a string, do nothing. Else, decode as UTF-8
                          'term': ((matches[0]).strings[0])[2] if isinstance(((matches[0]).strings[0])[2], str) else ((matches[0]).strings[0])[2].decode('UTF-8'),
                          'id': (((matches[0]).strings[0])[1])[1:]}
            # If it's blacklisted, announce and pass
            if components['rule'] == 'blacklist':
                lib.print_status(f"Blacklisted term detected: [{components['term']}]")
            # Otherwise, continue checking rules
            else:
                lib.general_matching(vars_dict, prescan_text, proch, components)
        #If no matches are found, it just writes it with the parameter as a name
        else:
            lib.print_status(f"No matches in document: /{proch}")
            codecs.open(f"{vars_dict['workpath']}{proch}.txt", 'w+', 'utf-8').write(prescan_text)
    else:
        codecs.open(f"{vars_dict['workpath']}{proch}.txt", 'w+', "utf-8").write(prescan_text)
# Scraping Function:
def non_api_search(vars_dict):
    """
    This function fetches the pastebin archive and all the pastes in it. It passes them to archive_engine(), then sleeps
    per the time specified by vars_dict['cooldown']

    :param vars_dict: dict of necessary variables returned from config()
    :return: Nothing
    """
    arch_runs = 0
    while True:
        lib.print_status(f"Runs: {arch_runs}")
        # Fetch the pastebin public archive
        lib.print_status(f"Getting archived pastes...")
        arch_page = lib.connect("https://pastebin.com/archive")
        arch_soup = BeautifulSoup(arch_page.text, 'html.parser')
        sleep(2)
        # Parse the archive HTML to get the individual document URLs
        lib.print_status(f"Finding params...")
        table = arch_soup.find("table", attrs={'class': "maintable"})
        tablehrefs = [(x + 1, y) for x, y in enumerate([a['href'] for a in table.findAll('a', href=True) if 'archive' not in a['href']])]
        # For each paste listed, connect and pass the text to archive_engine()
        for h in tablehrefs:
            proch = h[1][1:]
            lib.print_success(f"Acting on param {proch}  [{h[0]}/{len(tablehrefs)}]...")
            full_archpage = lib.connect(f"https://pastebin.com/{proch}")
            item_soup = BeautifulSoup(full_archpage.text, 'html.parser')
            # Fetch the raw text and pass to archive_engine()
            unprocessed = item_soup.find('textarea').contents[0]
            archive_engine(unprocessed, proch, vars_dict)
            # Increment the run
            arch_runs += 1
            sleep(vars_dict['limiter'])
        # if not running in a constant loop, check if the runs is greater or equal to the stop_input
        # If yes, exit. If no, continue
        if isinstance(vars_dict['stop_input'], int):
            if arch_runs >= vars_dict['stop_input']:
                lib.print_success(f"Runs Complete, Operation Finished...")
                exit()
        # Cooldown after all individual pastes are scanned
        lib.print_status(f"Pastes fetched, cooling down for {vars_dict['cooldown']} seconds...")
        sleep(vars_dict['cooldown'] / 2)
        lib.print_status(f"Halfway through cooldown")
        sleep(vars_dict['cooldown'] / 2)
        lib.print_status(f"resuming...")
        continue
# Main
def main(args):
    lib.print_title("""
    _________________________________________
    [                                       ]
    [                                       ]
    [           Welcome to BinBot           ]
    [            Made by Mili-NT            ]
    [                                       ]
    [_______________________________________]
    Note: To load a config file, pass it as an argument
    """)
    # If filepath is passed, it passes that to config().
    # If not, it passes an invalid path "" which results in manual setup
    vars_dict = config(args[1]) if len(args) > 1 else config("")
    try:
        non_api_search(vars_dict)
    except KeyboardInterrupt:
        lib.print_status(f"Operation cancelled...")

if __name__ == "__main__":
    main(sys.argv)

