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
from rich import box
from time import sleep
from rich import print
from rich.table import Table
from rich.panel import Panel
from os import path, listdir
from sys import path as syspath
from rich.console import Console
from rich.prompt import Prompt,Confirm, IntPrompt
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
        while True:
            workpath = Prompt.ask(lib.stylize("Enter the path you wish to save text documents to (Leave empty for current directory)", 'input'),
                                  default=syspath[0],
                                  show_default=False)
            if not path.isdir(workpath):
                print(lib.stylize("Invalid path, check input...", 'error'))
                continue
            print(lib.stylize("Valid Path...", 'success'))
            workpath = workpath if any([workpath.endswith('\\'), workpath.endswith('/')]) else f'{workpath}/'
            break
        saveall = Confirm.ask(lib.stylize("Save all documents (Enter N to only save matched documents)?", 'input'))
        # Services to Enable (services):
        # TODO: redesign this whole bit
        while True:
            for x in collectors.service_names.keys():
                print(lib.stylize(f"[{x}]: {collectors.service_names[x]}", 'status'))
            service_choice = Prompt.ask("Enter the number(s) of the services you wish to scrape, separated by a comma (Leave blank for All)",
                                        default="All",
                                        show_default=False)
            if service_choice == "All":
                services = [collectors.service_names[x] for x in collectors.service_names.keys()]
            else:
                services = [collectors.service_names[int(x)] for x in service_choice if int(x) in collectors.service_names.keys()]
            services = list(collectors.service_names.values()) if services == [] else services
            break
        # Looping
        stop_input = Confirm.ask(lib.stylize("Run in a constant loop?", 'input'))
        if not stop_input:
            stop_input = IntPrompt.ask(lib.stylize("Enter the amount of times you want to fetch the archives", 'input'))
            stop_input = True if stop_input <= 0 else stop_input
        # Limiter and Cooldown
        limiter = IntPrompt.ask(lib.stylize("Enter the request limit you wish to use (recommended: 5)", 'input'),
                                default=5,
                                show_default=False)
        cooldown = IntPrompt.ask(lib.stylize("Enter the cooldown between IP bans/Archive scrapes (recommended: 600)", 'input'),
                                default=600,
                                show_default=False)
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
            json.dump(vars_dict, open(f"config.json", 'w'))
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
        table = Table(title="Settings")
        table.add_column("Setting")
        table.add_column("Value", style="bold")
        for x in vars_dict.keys():
            if x != 'search_rules' and x != 'binary_rules':
                table.add_row(f"{x}", f"{vars_dict[x]}")
        console = Console()
        console.print(table)
    finally:
        print("\n")
        return vars_dict
# Main
def main(args):
    print(Panel.fit("[bold purple]Welcome to BinBot[/bold purple]",
                    subtitle="[bold purple]Made By Mili-NT[/[bold purple]",
                    subtitle_align="center",
                    padding=(2,20),
                    width=500,
                    box=box.ROUNDED),
                  justify="center")
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

