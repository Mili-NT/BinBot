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
from rich import print
from rich.prompt import Prompt,Confirm
from time import sleep
from os import path, listdir
from sys import path as syspath
from concurrent.futures import ThreadPoolExecutor

# Author: Mili
# No API key(s) needed

# TODO: error logging

# Setup Function:
def config(configpath):
    """
    :param configpath: path to config file, if it is blank or non-existent, it runs manual setup
    :return: vars_dict, a dictionary containing all the variables needed to run the main functions
    """
    # Manual Setup:
    if path.isfile(configpath) is False:
        # Saving options (workpath and saveall):
        workpath = Prompt.ask("Enter the path you wish to save text documents to (enter curdir for current directory)")
        while True:
            workpath = lib.print_input(
                "Enter the path you wish to save text documents to (enter curdir for current directory)")
            workpath = syspath[0] if workpath.lower() == 'curdir' else workpath
            if path.isdir(workpath):
                print(lib.stylize("Valid Path...", 'success'))
                workpath = workpath if any([workpath.endswith('\\'), workpath.endswith('/')]) else f'{workpath}/'
            else:
                print(lib.stylize("Invalid path, check input...", 'error'))
                continue
            break
        saveall = Confirm.ask(lib.stylize("Save all documents (Enter N to only save matched documents)?", 'input'))
        # Services to Enable (services):
        while True:
            for x in collectors.service_names.keys():
                print(lib.stylize(f"[{x}]: {collectors.service_names[x]}", 'status'))
            service_choice = lib.print_input("Enter the number(s) of the services you wish to scrape, "
                                       "separated by a comma").replace(" ", '').split(',')
            services = [collectors.service_names[int(x)] for x in service_choice if int(x) in collectors.service_names.keys()]
            services = list(collectors.service_names.values()) if services == [] else services
            break
        # Looping, Limiter, and Cooldown Input (stop_input, limiter, cooldown):
        while True:
            loop_input = lib.print_input("Run in a constant loop? [y]/[n]")
            if loop_input.lower() == 'y':
                stop_input = True
            else:
                stop_input = int(lib.print_input("Enter the amount of times you want to fetch the archives: "))
                # If they enter 0 or below pastes to fetch, run in an infinite loop:
                stop_input = True if stop_input <= 0 else stop_input
            # Limiter and Cooldown
            limiter = int(lib.print_input("Enter the request limit you wish to use (recommended: 5)"))
            cooldown = int(
                lib.print_input("Enter the cooldown between IP bans/Archive scrapes (recommended: 600)"))
            # If no values are entered, select the recommended
            limiter = 5 if any([limiter <= 0, isinstance(limiter, int) is False]) else limiter
            cooldown = 600 if any([cooldown <= 0, isinstance(cooldown, int) is False]) else cooldown
            break
        # YARA (yara_scanning)
        yara_scanning = Confirm.ask("Enabled scanning with YARA rules")
        # Building Settings Dict:
        vars_dict = {
            'workpath': workpath,
            'stop_input': stop_input,
            'limiter': limiter,
            'cooldown': cooldown,
            'yara_scanning': yara_scanning,
            'services': services,
            'saveall': saveall,
        }
        # Saving
        savechoice = Confirm.ask(lib.stylize('Save configuration to file for repeated use?', 'input'))
        if savechoice:
            configname = lib.print_input("Enter the config name (no extension)")
            configname = configname.split(".")[0] if '.json' in configname else configname
            json.dump(vars_dict, open(f"{configname}.json", 'w'))
    # Loading Config:
    else:
        vars_dict = json.load(open(configpath))
    # YARA Compilation:
    # YARA rules aren't written to files because they cant be serialized
    if vars_dict['yara_scanning']:
        vars_dict['search_rules'] = yara.compile(filepaths={f.split('.')[0]: path.join(f'{syspath[0]}/yara_rules/general_rules/', f) for f in listdir(f'{syspath[0]}/yara_rules/general_rules/') if path.isfile(path.join(f'{syspath[0]}/yara_rules/general_rules/', f)) and f.endswith(".yar") or f.endswith(".yara")})
        vars_dict['binary_rules'] = yara.compile(filepaths={f.split('.')[0]: path.join(f'{syspath[0]}/yara_rules/binary_rules/', f) for f in listdir(f'{syspath[0]}/yara_rules/binary_rules/') if path.isfile(path.join(f'{syspath[0]}/yara_rules/binary_rules/', f)) and f.endswith(".yar") or f.endswith(".yara")})
    # Display and Return:
    try:
        print("\n")
        # TODO: rich table
        for x in vars_dict.keys():
            if x != 'search_rules' and x != 'binary_rules':
                print(f"\x1b[94m[{x}]\x1b[0m: " + f"\x1b[1;32;40m{str(vars_dict[x])}\x1b[0m")
                print("\x1b[94m---------------------\x1b[0m")
    finally:
        print("\n")
        return vars_dict
# Main
def main(args):
    print(lib.stylize("""
    _________________________________________
    [                                       ]
    [                                       ]
    [           Welcome to BinBot           ]
    [            Made by Mili-NT            ]
    [                                       ]
    [_______________________________________]
    Note: To load a config file, pass it as an argument
    """, 'title'))
    # If filepath is passed, it passes that to config().
    # If not, it passes an invalid path "" which results in manual setup
    vars_dict = config(args[1]) if len(args) > 1 else config("")
    try:
        # This creates a thread for every service enabled
        runs = 0
        while True:
            with ThreadPoolExecutor(max_workers=len(vars_dict['services'])) as executor:
                for service in vars_dict['services']:
                    executor.submit(collectors.services[service], vars_dict)
            runs += 1
            # This line is a little weird, but due to True == 1 being True, isinstance(vars_dict['stop_input'], int)
            # wouldnt work.
            if str(vars_dict['stop_input']) != 'True':
                if runs >= vars_dict['stop_input']:
                    print(lib.stylize(f"Runs Complete, Operation Finished...", 'success'))
                    exit()
            print(lib.stylize(f"All services scraped, cooling down for {vars_dict['cooldown']} seconds", 'status'))
            sleep(vars_dict['cooldown'] / 2)
            print(lib.stylize("Halfway through cooldown.", 'status'))
            sleep(vars_dict['cooldown'] / 2)
            print(lib.stylize("Continuing...", 'status'))

    except KeyboardInterrupt:
        print(lib.stylize(f"Operation cancelled...", 'status'))
        exit()

if __name__ == "__main__":
    main(sys.argv)

