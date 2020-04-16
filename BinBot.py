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
import collectors
from os import path, listdir
from sys import path as syspath
from concurrent.futures import ThreadPoolExecutor

# Author: Mili
# No API key(s) needed

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
        # Services to Enable:
        while True:
            for x in collectors.service_names.keys():
                lib.print_status(f"[{x}]: {collectors.service_names[x]}")
            service_choice = lib.print_input("Enter the number(s) of the services you wish to scrape, "
                                       "separated by a comma").replace(" ", '').split(',')
            services = [collectors.service_names[int(x)] for x in service_choice if int(x) in collectors.service_names.keys()]
            services = list(collectors.service_names.values()) if services == [] else services
            break
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
                limiter = 5 if limiter <= 0 else limiter
                cooldown = 1200 if cooldown <= 0 else cooldown
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
            'yara_scanning': yara_scanning,
            'services': services
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
        # This creates a thread for every service enabled
        with ThreadPoolExecutor(max_workers=len(vars_dict['services'])) as executor:
            for service in vars_dict['services']:
                executor.submit(collectors.services[service], vars_dict)
    except KeyboardInterrupt:
        lib.print_status(f"Operation cancelled...")
        exit()

if __name__ == "__main__":
    main(sys.argv)

