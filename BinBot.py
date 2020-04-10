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

import re
import lib
import gzip
import yara
import codecs
import requests
from time import sleep
from base64 import b64decode
from datetime import datetime
from bs4 import BeautifulSoup
from sys import path as syspath
from configparser import ConfigParser
from os import path, listdir

# Author: Mili
# No API key needed

# Functions
def archive_connect():
    archive_url = "https://pastebin.com/archive/text"
    def print_connecterror():
        lib.print_error(f"\nException occurred: {e}\nPossible causes: Poor/Non-functioning Internet connection or pastebin is unreachable\nPossible fixes: Troubleshoot internet connection or check status of {archive_url}")
    def print_timeouterror():
        lib.print_error(f"\nException occurred: {e}\nPossible causes: Too many requests made to {archive_url}\nPossible fixes: Check firewall settings and check the status of {archive_url}.")
    def print_genericerror():
        lib.print_error(f"\nException occurred: {e}")
    while True:
        try:
            archive_page = requests.get(archive_url, headers=lib.random_headers())
            return archive_page
        except Exception as e:
            if e is requests.exceptions.ConnectionError:
                print_connecterror()
                break
            elif e is requests.exceptions.Timeout:
                print_timeouterror()
                break
            else:
                print_genericerror()
                break
def parameter_connect(proch):
    archive_url = "https://pastebin.com/archive/text"
    def print_connecterror():
        lib.print_error(f"\nException occurred: {e}\nPossible causes: Poor/Non-functioning Internet connection or pastebin is unreachable\nPossible fixes: Troubleshoot internet connection or check status of {archive_url}")
    def print_timeouterror():
        lib.print_error(f"\nException occurred: {e}\nPossible causes: Too many requests made to {archive_url}\nPossible fixes: Check firewall settings and check the status of {archive_url}.")
    def print_genericerror():
        lib.print_error(f"\nException occurred: {e}")
    while True:
        url_foundation = "https://pastebin.com/"
        full_arch_url = url_foundation + proch  # Generate URLs by adding the processed parameter to the base URL
        try:
            full_archpage = requests.get(full_arch_url, headers=lib.random_headers())
            return full_archpage, full_arch_url
        except Exception as e:
            if e is requests.exceptions.ConnectionError:
                print_connecterror()
                continue
            elif e is requests.exceptions.Timeout:
                print_timeouterror()
                continue
            else:
                print_genericerror()
                continue

def archive_engine(prescan_text, proch, vars_dict):
    if vars_dict['yara_scanning'] is True:
        matches = vars_dict['search_rules'].match(data=prescan_text)
        if matches:
            # Blacklist:
            if matches[0].rule == 'blacklist':
                lib.print_status(f"Blacklisted term detected: [{((matches[0]).strings[0])[2].decode('UTF-8')}]")
            else:
                # Base64 Artifacts
                if matches[0].rule == 'b64Artifacts':
                    lib.print_success(f"Base64 Artifact Found: [{((matches[0]).strings[0])[2].decode('UTF-8')}]")
                    decoded_content = b64decode(prescan_text)
                    if ((matches[0]).strings[0])[2].decode('UTF-8') == "H4sI":
                        decompressed_string = gzip.decompress(bytes(decoded_content, 'utf-8'))
                        with codecs.open(f"{vars_dict['workpath']}{proch}.file", 'w+', 'utf-8') as savefile:
                            savefile.write(decompressed_string)
                    else:
                        with codecs.open(f"{vars_dict['workpath']}{((matches[0]).strings[0])[1].decode('UTF-8').decode('UTF-8')}_{proch}.txt", 'w+', 'utf-8') as savefile:
                            savefile.write(decoded_content)
                # Other Rules:
                elif matches[0].rule == 'powershellArtifacts':
                    lib.print_success(f"Powershell Artifact Found: [{((matches[0]).strings[0])[2].decode('UTF-8')}]")
                    with codecs.open(f"{vars_dict['workpath']}{((matches[0]).strings[0])[2].decode('UTF-8')}_{proch}.ps1", 'w+', 'utf-8') as savefile:
                        savefile.write(prescan_text)
                elif matches[0].rule == 'keywords':
                    lib.print_success(f"Keyword found: [{((matches[0]).strings[0])[2].decode('UTF-8')}]")
                    with codecs.open(f"{vars_dict['workpath']}{((matches[0]).strings[0])[2].decode('UTF-8')}_{proch}.txt", 'w+', 'utf-8') as savefile:
                        savefile.write(prescan_text)
                else:
                    with codecs.open(f"{vars_dict['workpath']}{((matches[0]).strings[0])[2].decode('UTF-8')}_{proch}.txt", 'w+', 'utf-8') as savefile:
                        savefile.write(prescan_text)
        else:
            with codecs.open(f"{vars_dict['workpath']}{proch}.txt", 'w+', 'utf-8') as savefile:
                savefile.write(prescan_text)
    else:
        with codecs.open(f"{vars_dict['workpath']}{proch}.txt", 'w+', "utf-8") as savefile:
            savefile.write(prescan_text)
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
            arch_page = archive_connect()
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
            table = arch_soup.findAll("table", attrs={'class': "maintable"}) # Fetch the table of recent pastes
            while True:
                try:
                    tablehrefs = [a for a in table[0].findAll('a', href=True) if 'archive' not in a['href']]
                    break
                except AttributeError:
                    lib.print_error(f"IP Temporarily suspending, pausing until the ban is lifted. Estimated time: one hour...")
                    sleep(vars_dict['cooldown'])
                    lib.print_error(f"Process resumed...")
                    continue
            for h in tablehrefs:
                proch = (h['href']).replace("/", "") # fetch the URL param for each paste
                lib.print_success("params fetched...")
                lib.print_status(f"Acting on param {proch}...")
                full_archpage, full_arch_url = parameter_connect(proch)
                item_soup = BeautifulSoup(full_archpage.text, 'html.parser')
                unprocessed = item_soup.find('textarea') # Fetch the raw text in the paste.
                taglist = [
                    '<textarea class="paste_code" id="paste_code" name="paste_code" onkeydown="return catchTab(this,event)">',
                    '<textarea class="paste_code" id="paste_code" name="paste_code" onkeydown="return catchTab(this,event)">',
                    '<textarea class="paste_textarea" id="paste_code" name="paste_code" onkeydown="return catchTab(this,event)" rows="10">',
                    '</textarea>', '<textarea class="paste_code" id="paste_code" name="paste_code" onkeydown="return catchTab(this,event)">',
                ]
                for tag in taglist:
                    unprocessed = str(unprocessed).replace(tag, "") # process the raw text by removing html tags
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

