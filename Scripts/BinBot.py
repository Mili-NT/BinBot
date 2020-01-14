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
import codecs
import requests
from os import path, name, getcwd
from time import sleep
from datetime import datetime
from bs4 import BeautifulSoup
from sys import path as syspath
from configparser import ConfigParser

# Author: Mili
# Python Version: 3.6.0
# No API key needed

# Functions
def archive_connect():
    archive_url = "https://pastebin.com/archive/text"
    def print_connecterror():
        lib.PrintError(f"\nException occurred: {e}\nPossible causes: Poor/Non-functioning Internet connection or pastebin is unreachable\nPossible fixes: Troubleshoot internet connection or check status of {archive_url}")
    def print_timeouterror():
        lib.PrintError(f"\nException occurred: {e}\nPossible causes: Too many requests made to {archive_url}\nPossible fixes: Check firewall settings and check the status of {archive_url}.")
    def print_genericerror():
        lib.PrintError(f"\nException occurred: {e}")
    while True:
        try:
            archive_page = requests.get(archive_url, headers=lib.RandomHeaders())
            today = datetime.now().strftime('%x')
            now = datetime.now().strftime('%X')
            creationdate = today + '~' + now
            identifier = creationdate.replace("/", ".").replace(":", "-")
            archive_filename = "[" + str(identifier) + "]"
            return archive_page, archive_filename
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

def archive_engine(prescan_text, vars_dict):
    if vars_dict['keylisting'] is True:
        for k in vars_dict['key_list']:
            if k.lower() in prescan_text.lower():
                today = datetime.now().strftime('%x')
                now = datetime.now().strftime('%X')
                creationdate = f"{today}~{now}"
                keyfilename = f"[Keyword- {k}]{creationdate}".replace("/", ".").replace(":", "-")
                keyfi = codecs.open(f'{vars_dict["workpath"]}{keyfilename}'.replace(":", "-").replace(":", "-").replace("/", "-") + ".txt", 'w+', 'utf-8')
                keyfi.write(prescan_text)
                keyfi.close()
            else:
                pass
    if vars_dict['reglisting'] is True:
        count = 0
        for regex_pattern in vars_dict['reglist']:
            count += 1
            for match in re.findall(regex_pattern, prescan_text):
                today = datetime.now().strftime('%x')
                now = datetime.now().strftime('%X')
                creationdate = f"{today}~{now}"
                regexfilename = f"[Pattern [{str(count)}]]{creationdate}".replace("/", ".").replace(":", "-")
                regfi = codecs.open(f'{vars_dict["workpath"]}{regexfilename}'.replace(":", "-").replace(":", "-").replace("/", "-") + ".txt", 'w+','utf-8')
                regfi.write(str(match))
                regfi.close()

def parameter_connect(proch):
    archive_url = "https://pastebin.com/archive/text"
    def print_connecterror():
        lib.PrintError(f"\nException occurred: {e}\nPossible causes: Poor/Non-functioning Internet connection or pastebin is unreachable\nPossible fixes: Troubleshoot internet connection or check status of {archive_url}")
    def print_timeouterror():
        lib.PrintError(f"\nException occurred: {e}\nPossible causes: Too many requests made to {archive_url}\nPossible fixes: Check firewall settings and check the status of {archive_url}.")
    def print_genericerror():
        lib.PrintError(f"\nException occurred: {e}")
    while True:
        url_foundation = "https://pastebin.com"
        full_arch_url = url_foundation + proch  # Generate URLs by adding the processed parameter to the base URL
        try:
            full_archpage = requests.get(full_arch_url, headers=lib.RandomHeaders())
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

def Non_API_Search(vars_dict):
    arch_runs = 0
    while True:
        if arch_runs > 0:
            lib.PrintStatus(f"Runs: {arch_runs}")
            if arch_runs >= vars_dict['stop_input'] and vars_dict['stop_input'] is False:
                lib.PrintSuccess(f"Runs Complete, Operation Finished... [{datetime.now().strftime('%X')}]")
                exit()
            else:
                lib.PrintStatus(f"Pastes fetched, cooling down for {vars_dict['cooldown']} seconds... [{datetime.now().strftime('%X')}]")
                sleep(vars_dict['cooldown']/2)
                lib.PrintStatus(f"Halfway through at [{datetime.now().strftime('%X')}]")
                sleep(vars_dict['cooldown']/2)
                lib.PrintStatus(f"resuming... [{datetime.now().strftime('%X')}]")
        if arch_runs < vars_dict['stop_input'] or vars_dict['stop_input'] is True:
            arch_page, arch_filename = archive_connect()
            arch_soup = BeautifulSoup(arch_page.text, 'html.parser')
            sleep(2)
            lib.PrintStatus(f"Getting archived pastes... [{datetime.now().strftime('%X')}]")
            if 'access denied' in arch_page.text:
                lib.PrintError(f"IP Temporarily suspending, pausing until the ban is lifted. Estimated time: one hour... [{datetime.now().strftime('%X')}]")
                sleep(vars_dict['cooldown'])
                lib.PrintStatus(f"Process resumed... [{datetime.now().strftime('%X')}]")
                continue
            else:
                pass
            lib.PrintStatus(f"Finding params...[{datetime.now().strftime('%X')}]")
            table = arch_soup.find("table", class_="maintable") # Fetch the table of recent pastes
            while True:
                try:
                    tablehrefs = table.findAll('a', href=True) # Find the <a> tags for every paste
                    break
                except AttributeError:
                    lib.PrintError(f"IP Temporarily suspending, pausing until the ban is lifted. Estimated time: one hour... [{datetime.now().strftime('%X')}]")
                    sleep(vars_dict['cooldown'])
                    lib.PrintError(f"Process resumed... [{datetime.now().strftime('%X')}]")
                    continue
            for h in tablehrefs:
                proch = h['href'] # fetch the URL param for each paste
                lib.PrintSuccess("params fetched... [" + str(datetime.now().strftime('%X')) + "]")
                lib.PrintStatus(f"Acting on param {proch}... [{datetime.now().strftime('%X')}]")
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
                if vars_dict['arch_mode'] == 'r':
                    if vars_dict['blacklisting'] is True:
                        flagged = False
                        compare_text = re.sub(r'\s+', '', unprocessed) # strip all whitespace for comparison
                        for b in vars_dict['blacklist']:
                            b = re.sub(r'\s+', '', b) # strip all whitespace for comparison
                            if b.lower() in compare_text.lower():
                                lib.PrintStatus("Blacklisted phrase detected, passing...")
                                flagged = True
                        if flagged is True:
                            continue
                    arch_final_file = codecs.open(str(vars_dict['workpath']) + str(proch) + ".txt", 'w+', 'utf-8')
                    arch_final_file.write(unprocessed)
                    arch_final_file.close()
                    arch_runs += 1
                    sleep(vars_dict['limiter'])
                    continue
                elif vars_dict['arch_mode'] == 'f':
                    if path.isdir(vars_dict['workpath']) is True:
                        lib.PrintStatus(f"Running engine... [{datetime.now().strftime('%X')}]")
                        if vars_dict['blacklisting'] is True:
                            flagged = False
                            compare_text = re.sub(r'\s+', '', unprocessed)  # strip all whitespace for comparison
                            for b in vars_dict['blacklist']:
                                b = re.sub(r'\s+', '', b)  # strip all whitespace for comparison
                                if b.lower() in compare_text.lower():
                                    lib.PrintStatus("Blacklisted phrase detected, passing...")
                                    flagged = True
                            if flagged is True:
                                continue
                        lib.PrintStatus(f"Running engine... [{datetime.now().strftime('%X')}]")
                        archive_engine(unprocessed, vars_dict)
                        arch_runs += 1
                        sleep(vars_dict['limiter'])
                        continue
        else:
            lib.PrintSuccess(f"Operation Finished... [{datetime.now().strftime('%X')}]")
            break

def manual_setup():
    # Save path
    while True:
        workpath = lib.PrintInput("Enter the path you wish to save text documents to (enter curdir for current directory)")
        if workpath.lower() == 'curdir':
            if name.lower() == 'nt':
                workpath = getcwd()
            else:
                workpath = syspath[0]
        if path.isdir(workpath):
            lib.PrintSuccess("Valid Path...")
            if workpath.endswith('\\') or workpath.endswith('/'):
                pass
            else:
                if name.lower == 'nt':
                    workpath = workpath + str('\\')
                else:
                    workpath = workpath + str('/')
            break
        else:
            lib.PrintError("Invalid path, check input...")
            continue
    # Looping
    while True:
        try:
            stopinput_input = lib.PrintInput("Run in a constant loop? [y]/[n]")
            if stopinput_input.lower() == 'y':
                stop_input = True
            elif stopinput_input.lower() == 'n':
                stop_input = int(lib.PrintInput("Enter the amount of successful pulls you wish to make (enter 0 for infinite)"))
            # Limiter and Cooldown
            try: limiter = int(lib.PrintInput("Enter the request limit you wish to use (recommended: 5)"))
            except: limiter = 5
            try: cooldown = int(lib.PrintInput("Enter the cooldown between IP bans/Archive scrapes (recommended: 1200)"))
            except: cooldown = 1200
            break
        except ValueError:
            lib.PrintError("Invalid Input.")
            continue
    # Blacklisting
    while True:
        blacklist = []
        list_choice = lib.PrintInput("Utilize blacklisting to avoid spam documents [y]/[n]")
        if list_choice.lower() == 'y':
            blacklisting = True
            while True:
                bfile_input = lib.PrintInput("Read blacklisted terms from file? [y]/[n]")
                if bfile_input.lower() == 'n':
                    blacklist_input = lib.PrintInput("Enter the phrases you wish to blacklist separated by a comma").split(",")
                    for b in blacklist_input:
                        blacklist.append(b)
                    break
                elif bfile_input.lower() == 'y':
                    lib.PrintStatus("File should be structured with one term per line, with no comma.")
                    bpath = lib.PrintInput("Enter the full path of the file")
                    if path.isfile(bpath) is True:
                        print("Blacklist file detected...")
                        with open(bpath) as bfile:
                            for bline in bfile.readlines():
                                blacklist.append(bline.rstrip())
                        break
            break
        elif list_choice.lower() == 'n':
            blacklisting = False
            break
        else:
            lib.PrintError("invalid input.")
            continue
    # Filtering
    while True:
        reglist = []
        amode_input = lib.PrintInput("[r]aw or [f]iltered search (filtered search will make use of the ArchiveEngine and will return fewer results)")
        if amode_input.lower() == 'r':
            arch_mode = 'r'
            keylisting = False
            key_list = []
            reglisting = False
            reglist = []
            break
        elif amode_input.lower() == 'f':
            arch_mode = 'f'
            keychoice = lib.PrintInput("Enable keyword filtering [True]/[False]")
            if keychoice.lower() in ['true', 't']:
                keylisting = True
            else:
                keylisting = False
                key_list = []
            regchoice = lib.PrintInput("Enable regular expression filtering [True]/[False]")
            if regchoice.lower() in ['true', 't']:
                reglisting = True
            else:
                reglisting = False
                reglist = []
            if keylisting is False and reglisting is False:
                arch_mode = 'r'
            break
    # Filtering Input
    if keylisting is True:
        while True:
            filechoice = lib.PrintInput("Load keywords from file: [y]/[n]")
            if filechoice.lower() == 'y':
                filterfile_input = lib.PrintInput("Enter full path of the file")
                if path.isfile(filterfile_input):
                    lib.PrintSuccess("keylist file detected...")
                    pass
                else:
                    lib.PrintError("No Such File Found.")
                    continue
                with open(filterfile_input) as filterfile:
                    for lines in filterfile.readlines():
                        key_list.append(lines.rstrip())
                    break
            elif filechoice.lower() == 'n':
                keyword_input = lib.PrintInput("Enter the keywords you'd like to search for, seperated by a comma").split(",")
                for k in keyword_input:
                    key_list.append(k)
                break
    if reglisting is True:
        while True:
            regfilechoice = lib.PrintInput("Load regex from file (one pattern per line)? [y]/[n]")
            if regfilechoice.lower() not in ['y', 'n']:
                lib.PrintError("Invalid Input")
                continue
            elif regfilechoice.lower() == 'y':
                while True:
                    regpath = lib.PrintInput('Enter the full path (including extension) to the pattern file')
                    if path.isfile(regpath) is False:
                        lib.PrintError("No such file found.")
                        continue
                    else:
                        with open(regpath, 'r') as regfile:
                            for line in regfile.readlines():
                                reglist.append(line.rstrip())
                        break
                break
    # Saving
    while True:
        savechoice = lib.PrintInput('Save configuration to file for repeated use? [y]/[n]')
        if savechoice.lower() == 'n':
            break
        elif savechoice.lower() == 'y':
            configname = lib.PrintInput("Enter the config name (no extension)")
            try:
                with open(configname + '.ini', 'w+') as cfile:
                    cfile.write(
f"""[initial_vars]
workpath = {workpath}
stop_input = {stop_input}
limiter = {limiter}
cooldown = {cooldown}
blacklisting = {blacklisting}
blacklist = {blacklist}
reglisting = {reglisting}
reglist = {reglist}
keylisting = {keylisting}
key_list = {key_list}
arch_mode = {arch_mode}""")
                    break
            except Exception as e:
                print(f"{e}")
                break
    vars_dict = {
        'workpath': workpath,
        'stop_input': stop_input,
        'limiter': limiter,
        'cooldown': cooldown,
        'blacklisting': blacklisting,
        'blacklist': blacklist,
        'reglisting': reglisting,
        'reglist': reglist,
        'keylisting': keylisting,
        'key_list': key_list,
        'arch_mode': arch_mode
    }
    return vars_dict

def load_config():
    parser = ConfigParser()
    while True:
        configpath = lib.PrintInput('Enter the full path of the config file')
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
            blacklisting = parser.get('initial_vars', 'blacklisting')
            blacklist = parser.get('initial_vars', 'blacklist')
            reglisting = parser.getboolean('initial_vars', 'reglisting')
            reglist = parser.get('initial_vars', 'reglist')
            keylisting = parser.getboolean('initial_vars', 'keylisting')
            key_list = parser.get('initial_vars', 'key_list')
            arch_mode = parser.get('initial_vars', 'arch_mode')
            break
        else:
            lib.PrintError("No such file found")
            continue
    vars_dict = {
        'workpath': workpath,
        'stop_input': stop_input,
        'limiter': limiter,
        'cooldown': cooldown,
        'blacklisting': blacklisting,
        'blacklist': blacklist,
        'reglisting': reglisting,
        'reglist': reglist,
        'keylisting': keylisting,
        'key_list': key_list,
        'arch_mode': arch_mode
    }
    return vars_dict

# Main
def main():
    print("""
    _________________________________________
    [                                       ]
    [                                       ]
    [           Welcome to BinBot           ]
    [            Made by Mili-NT            ]
    [                                       ]
    [_______________________________________]
    """)
    while True:
        configchoice = lib.PrintInput("Load config file? [y]/[n]")
        if configchoice.lower() == 'y':
            vars_dict = load_config()
        elif configchoice.lower() in ['no', 'n']:
            vars_dict = manual_setup()
        Non_API_Search(vars_dict)

if __name__ == "__main__":
    main()
