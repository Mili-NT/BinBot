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

import lib
import gzip
import yara
import codecs
import requests
from time import sleep
from base64 import b64decode
from bs4 import BeautifulSoup
from sys import path as syspath
from configparser import ConfigParser
from os import path, listdir

# Author: Mili
# No API key needed

# Functions
def connect(url):
    try:
        return requests.get(url, headers=lib.random_headers())
    except Exception as e:
        lib.print_error(e)

def archive_engine(prescan_text, proch, vars_dict):
    if vars_dict['yara_scanning'] is True:
        matches = vars_dict['search_rules'].match(data=prescan_text)
        # If there are matches, it saves them under different names
        if matches:
            components = {'rule': matches[0].rule,
                          'term': ((matches[0]).strings[0])[2].decode('UTF-8'),
                          'id': ((matches[0]).strings[0])[1].decode('UTF-8')}
            # If it's blacklisted, announce and pass
            if components['rule'] == 'blacklist':
                lib.print_status(f"Blacklisted term detected: [{components['term']}]")
            # Otherwise, continue checking rules
            else:
                # The prebuilt rules:
                if components['rule'] == 'b64Artifacts':
                    lib.print_success(f"Base64 Artifact Found: [{components['term']}]")
                    # If gzipped, decompress:
                    if components['term'] == "H4sI":
                        codecs.open(f"{vars_dict['workpath']}{proch}.file", 'w+', 'utf-8').write(gzip.decompress(bytes(b64decode(prescan_text), 'utf-8')))
                    # Otherwise, decode and save:
                    else:
                        codecs.open(f"{vars_dict['workpath']}{components['id']}_{proch}.txt", 'w+', 'utf-8').write(b64decode(prescan_text))
                elif components['rule'] == 'powershellArtifacts':
                    lib.print_success(f"Powershell Artifact Found: [{components['term']}]")
                    codecs.open(f"{vars_dict['workpath']}{components['term']}_{proch}.ps1", 'w+', 'utf-8').write(prescan_text)
                elif components['rule'] == 'keywords':
                    lib.print_success(f"Keyword found: [{components['term']}]")
                    codecs.open(f"{vars_dict['workpath']}{components['term']}_{proch}.txt", 'w+', 'utf-8').write(prescan_text)
                # Custom rules will be saved by this statement:
                else:
                    codecs.open(f"{vars_dict['workpath']}{components['term']}_{proch}.txt", 'w+', 'utf-8').write(prescan_text)
        #If no matches are found, it just writes it with the parameter as a name
        else:
            lib.print_status(f"No matches in document: /{proch}")
            codecs.open(f"{vars_dict['workpath']}{proch}.txt", 'w+', 'utf-8').write(prescan_text)
    else:
        codecs.open(f"{vars_dict['workpath']}{proch}.txt", 'w+', "utf-8").write(prescan_text)
def Non_API_Search(vars_dict):
    arch_runs = 0
    while True:
        if arch_runs > 0:
            lib.print_status(f"Runs: {arch_runs}")
            if arch_runs >= vars_dict['stop_input'] and vars_dict['stop_input'] is False:
                lib.print_success(f"Runs Complete, Operation Finished...")
                exit()
            else:
                lib.print_status(f"Pastes fetched, cooling down for {vars_dict['cooldown']} seconds...")
                sleep(vars_dict['cooldown']/2)
                lib.print_status(f"Halfway through cooldown")
                sleep(vars_dict['cooldown']/2)
                lib.print_status(f"resuming...")
        if arch_runs < vars_dict['stop_input'] or vars_dict['stop_input'] is True:
            arch_page = connect("https://pastebin.com/archive")
            arch_soup = BeautifulSoup(arch_page.text, 'html.parser')
            sleep(2)
            lib.print_status(f"Getting archived pastes...")
            if 'access denied' in arch_page.text:
                lib.print_error(f"IP Temporarily suspending, pausing until the ban is lifted. Estimated time: one hour...")
                sleep(vars_dict['cooldown'])
                lib.print_status(f"Process resumed...")
                continue
            else:
                pass
            lib.print_status(f"Finding params...")
            table = arch_soup.find("table", attrs={'class': "maintable"})
            tablehrefs = [a['href'] for a in table.findAll('a', href=True) if 'archive' not in a['href']]
            for h in tablehrefs:
                proch = h[1:]
                lib.print_success(f"params fetched...\nActing on param {proch}...")
                full_archpage = connect(f"https://pastebin.com/{proch}")
                item_soup = BeautifulSoup(full_archpage.text, 'html.parser')
                unprocessed = item_soup.find('textarea').contents[0] # Fetch the raw text in the paste.
                archive_engine(unprocessed, proch, vars_dict)
                arch_runs += 1
                sleep(vars_dict['limiter'])
                continue
        else:
            lib.print_success(f"Operation Finished...")
            break

def manual_setup():
    # Save path
    while True:
        workpath = lib.print_input("Enter the path you wish to save text documents to (enter curdir for current directory)")
        if workpath.lower() == 'curdir':
            workpath = syspath[0]
        if path.isdir(workpath):
            lib.print_success("Valid Path...")
            if workpath.endswith('\\') or workpath.endswith('/'):
                pass
            else:
                workpath = workpath + str('/')
            break
        else:
            lib.print_error("Invalid path, check input...")
            continue
    # Looping
    while True:
        try:
            stopinput_input = lib.print_input("Run in a constant loop? [y]/[n]")
            if stopinput_input.lower() == 'y':
                stop_input = True
            elif stopinput_input.lower() == 'n':
                stop_input = int(lib.print_input("Enter the amount of successful pulls you wish to make (enter 0 for infinite)"))
            # Limiter and Cooldown
            try: limiter = int(lib.print_input("Enter the request limit you wish to use (recommended: 5)"))
            except: limiter = 5
            try: cooldown = int(lib.print_input("Enter the cooldown between IP bans/Archive scrapes (recommended: 1200)"))
            except: cooldown = 1200
            break
        except ValueError:
            lib.print_error("Invalid Input.")
            continue
    while True:
        yara_choice = lib.print_input("Enable scanning documents using YARA rules? [y/n]")
        if yara_choice.lower() not in ['y', 'n', 'yes', 'no']:
            lib.print_error("Invalid Input.")
            continue
        elif yara_choice.lower() in ['y', 'yes']:
            yara_scanning = True
            break
        elif yara_choice.lower() in ['n', 'no']:
            yara_scanning = False
            break
    # Yara Compiling
    if yara_scanning is True:
        yara_dir = f"{syspath[0]}/yara_rules"
        search_rules = yara.compile(
            filepaths={f.replace(".yar", ""): path.join(f'{yara_dir}/general_rules/', f) for f in listdir(f'{yara_dir}/general_rules/') if
                       path.isfile(path.join(yara_dir, f)) and f.endswith(".yar")})
        binary_rules = yara.compile(
            filepaths={f.replace(".yar", ""): path.join(f'{yara_dir}/binary_rules/', f) for f in listdir(f'{yara_dir}/binary_rules/') if
                       path.isfile(path.join(yara_dir, f)) and f.endswith(".yar")})
    else:
        search_rules = []
        binary_rules = []
    # Saving
    while True:
        savechoice = lib.print_input('Save configuration to file for repeated use? [y]/[n]')
        if savechoice.lower() == 'n':
            break
        elif savechoice.lower() == 'y':
            configname = lib.print_input("Enter the config name (no extension)")
            try:
                with open(configname + '.ini', 'w+') as cfile:
                    cfile.write(
f"""[initial_vars]
workpath = {workpath}
stop_input = {stop_input}
limiter = {limiter}
cooldown = {cooldown}
yara_scanning = {yara_scanning}""")
                    break
            except Exception as e:
                print(f"{e}")
                break
    vars_dict = {
        'workpath': workpath,
        'stop_input': stop_input,
        'limiter': limiter,
        'cooldown': cooldown,
        'yara_scanning': yara_scanning,
        'search_rules': search_rules,
        'binary_rules': binary_rules,
    }
    try:
        print("\n")
        for x in vars_dict.keys():
            if x != 'search_rules' and x != 'binary_rules':
                print(f"\x1b[94m[{x}]\x1b[0m: " + f"\x1b[1;32;40m{str(vars_dict[x])}\x1b[0m")
                print("\x1b[94m---------------------\x1b[0m")
    finally:
        print("\n")
    return vars_dict
def load_config():
    parser = ConfigParser()
    while True:
        configpath = lib.print_input('Enter the full path of the config file')
        if path.isfile(configpath) is True:
            parser.read(configpath, encoding='utf-8-sig')
            workpath = parser.get('initial_vars', 'workpath')
            stop_input = parser.get('initial_vars', 'stop_input')
            if stop_input == str('True'):
                stop_input = True
            else:
                stop_input = int(stop_input)
            limiter = int(parser.get('initial_vars', 'limiter'))
            cooldown = int(parser.get('initial_vars', 'cooldown'))
            yara_scanning = parser.getboolean('initial_vars', 'yara_scanning')
            if yara_scanning is True:
                yara_dir = f"{syspath[0]}/yara_rules"
                search_rules = yara.compile(
                    filepaths={f.replace(".yar", ""): path.join(f'{yara_dir}/general_rules/', f) for f in
                               listdir(f'{yara_dir}/general_rules/') if
                               path.isfile(path.join(yara_dir, f)) and f.endswith(".yar")})
                binary_rules = yara.compile(
                    filepaths={f.replace(".yar", ""): path.join(f'{yara_dir}/binary_rules/', f) for f in
                               listdir(f'{yara_dir}/binary_rules/') if
                               path.isfile(path.join(yara_dir, f)) and f.endswith(".yar")})
            else:
                search_rules = []
                binary_rules = []
            break
        else:
            lib.print_error("No such file found")
            continue
    vars_dict = {
        'workpath': workpath,
        'stop_input': stop_input,
        'limiter': limiter,
        'cooldown': cooldown,
        'yara_scanning': yara_scanning,
        'search_rules': search_rules,
        'binary_rules': binary_rules,
    }
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
def main():
    lib.print_title("""
    _________________________________________
    [                                       ]
    [                                       ]
    [           Welcome to BinBot           ]
    [            Made by Mili-NT            ]
    [                                       ]
    [_______________________________________]
    """)
    while True:
        configchoice = lib.print_input("Load config file? [y]/[n]")
        if configchoice.lower() not in ['y', 'n', 'yes', 'no']:
            lib.print_error("Invalid Input.")
            continue
        elif configchoice.lower() in ['y', 'yes']:
            vars_dict = load_config()
            break
        elif configchoice.lower() in ['no', 'n']:
            vars_dict = manual_setup()
            break
    try:
        Non_API_Search(vars_dict)
    except KeyboardInterrupt:
        lib.print_status(f"Operation cancelled...")

if __name__ == "__main__":
    main()

