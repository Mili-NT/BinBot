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
from os import path
from time import sleep
from datetime import datetime
from bs4 import BeautifulSoup
from sys import path as syspath
from configparser import ConfigParser


# Author: Mili
# Python Version: 3.6.0
# No API key needed

#
# Variables, Setup, and Misc
#
parser = ConfigParser()
curdir = syspath[0]

key_list = []
blacklist = []
reglist = []

taglist = ['<textarea class="paste_code" id="paste_code" name="paste_code" onkeydown="return catchTab(this,event)">',
           '<textarea class="paste_textarea" id="paste_code" name="paste_code" onkeydown="return catchTab(this,event)" rows="10">',
           '</textarea>']

archive_url = "https://pastebin.com/archive/text"
scrape_url = "https://scrape.pastebin.com/api_scrape_item.php?i="
url_foundation = "https://pastebin.com"

ConnectError = "<title>Pastebin.com - Page Removed</title>"
AccessDeniedError = "access denied"

#
# Functions
#
def archive_connect():
    def print_connecterror():
        lib.PrintError(f"""
    Exception occurred: {e}
    Possible causes: Poor/Non-functioning Internet connection or pastebin is unreachable
    Possible fixes: Troubleshoot internet connection or check status of {archive_url}
            """)
    def print_timeouterror():
        lib.PrintError(f"""
    Exception occurred: {e}
    Possible causes: Too many requests made to {archive_url}
    Possible fixes: Check firewall settings and check the status of {archive_url}.
            """)
    def print_genericerror():
        lib.PrintError(f"""
    Exception occurred: {e}
            """)

    while True:
        try:
            archive_page = requests.get(archive_url,headers=lib.RandomHeaders())
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

def archive_engine(prescan_text, keylistingchoice, reglistingchoice):
    if keylistingchoice is True:
        for k in  key_list:
            if k.lower() in prescan_text.lower():
                today = datetime.now().strftime('%x')
                now = datetime.now().strftime('%X')
                creationdate = today + '~' + now
                keyfilename = f"[Keyword- {k}]{creationdate}".replace("/", ".").replace(":", "-")
                keyfi = codecs.open(f'{workpath}{keyfilename}'.replace(":", "-").replace(":", "-").replace("/", "-") + ".txt", 'w+', 'utf-8')
                keyfi.write(prescan_text)
                keyfi.close()
            else:
                pass
    if reglistingchoice is True:
        count = 0
        if reglisting is True:
            for regex_pattern in reglist:
                count += 1
                for match in re.findall(regex_pattern, prescan_text):
                    today = datetime.now().strftime('%x')
                    now = datetime.now().strftime('%X')
                    creationdate = today + '~' + now
                    regexfilename = f"[Pattern [{str(count)}]]{creationdate}".replace("/", ".").replace(":", "-")
                    regfi = codecs.open(f'{workpath}{regexfilename}'.replace(":", "-").replace(":", "-").replace("/", "-") + ".txt", 'w+','utf-8')
                    regfi.write(str(match))
                    regfi.close()

def parameter_connect(proch):
    def print_connecterror():
        lib.PrintError(f"""
    Exception occurred: {e}
    Possible causes: Poor/Non-functioning Internet connection or pastebin is unreachable
    Possible fixes: Troubleshoot internet connection or check status of {archive_url}
            """)
    def print_timeouterror():
        lib.PrintError(f"""
    Exception occurred: {e}
    Possible causes: Too many requests made to {archive_url}
    Possible fixes: Check firewall settings and check the status of {archive_url}.
            """)
    def print_genericerror():
        lib.PrintError(f"""
    Exception occurred: {e}
            """)

    while True:
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

def ArchiveSearch(stop, amode):
    arch_runs = 0
    while True:
        if arch_runs > 0:
            lib.PrintStatus("Runs: "+str(arch_runs))
            if arch_runs >= stop and stop is False:
                lib.PrintSuccess("Runs Complete, Operation Finished... [" + str(datetime.now().strftime('%X')) + "]")
                exit()
            else:
                lib.PrintStatus("Pastes fetched, cooling down for "+str(cooldown)+" seconds... ["+str(datetime.now().strftime('%X'))+"]")
                sleep(cooldown/2)
                lib.PrintStatus("Halfway through at ["+str(datetime.now().strftime('%X'))+"]")
                sleep(cooldown/2)
                lib.PrintStatus("resuming... ["+str(datetime.now().strftime('%X'))+"]")
        if arch_runs < stop or stop is True:
            arch_page, arch_filename = archive_connect()
            arch_soup = BeautifulSoup(arch_page.text, 'html.parser')
            sleep(2)
            lib.PrintStatus("Getting archived pastes... ["+str(datetime.now().strftime('%X'))+"]")
            if AccessDeniedError in arch_page.text:
                lib.PrintError("IP Temporarily suspending, pausing until the ban is lifted. Estimated time: one hour... ["+str(datetime.now().strftime('%X'))+"]")
                sleep(cooldown)
                lib.PrintStatus("Process resumed... ["+str(datetime.now().strftime('%X'))+"]")
                continue
            else:
                pass
            lib.PrintStatus("Finding params... ["+str(datetime.now().strftime('%X'))+"]")


            table = arch_soup.find("table", class_="maintable") # Fetch the table of recent pastes
            while True:
                try:
                    tablehrefs = table.findAll('a', href=True) # Find the <a> tags for every paste
                    break
                except AttributeError:
                    lib.PrintError("IP Temporarily suspending, pausing until the ban is lifted. Estimated time: one hour... ["+str(datetime.now().strftime('%X'))+"]")
                    sleep(cooldown)
                    lib.PrinrError("Process resumed... ["+str(datetime.now().strftime('%X'))+"]")
                    continue

            for h in tablehrefs:
                proch = h['href'] # fetch the URL param for each paste
                lib.PrintSuccess("params fetched... ["+str(datetime.now().strftime('%X'))+"]")
                lib.PrintStatus("Acting on param "+str(proch)+"... ["+str(datetime.now().strftime('%X'))+"]")
                full_archpage, full_arch_url = parameter_connect(proch)
                sleep(5)
                item_soup = BeautifulSoup(full_archpage.text, 'html.parser')
                unprocessed = item_soup.find('textarea') # Fetch the raw text in the paste.
                for tag in taglist:
                    unprocessed = str(unprocessed).replace(tag, "") # process the raw text by removing all html elements
                if amode == 'r':
                    if path.isdir(workpath) is True:
                        if blacklisting is True:
                            flagged = False
                            compare_text = re.sub(r'\s+', '', unprocessed) # strip all whitespace for comparison
                            for b in blacklist:
                                b = re.sub(r'\s+', '', b) # strip all whitespace for comparison
                                if b.lower() in compare_text.lower():
                                    lib.PrintStatus("Blacklisted phrase detected, passing...")
                                    flagged = True

                            if flagged is True:
                                continue
                            else:
                                arch_final_file = codecs.open(str(workpath) + str(full_arch_url).replace(":", "-")
                                                              .replace(":", "-").replace("/", "-") + ".txt", 'w+', 'utf-8')
                                arch_final_file.write(unprocessed)
                                arch_final_file.close()
                                arch_runs += 1
                                continue
                        elif blacklisting is False:
                            arch_final_file = codecs.open(str(workpath) + str(full_arch_url).replace(":", "-")
                                                          .replace(":", "-").replace("/", "-") + ".txt", 'w+', 'utf-8')
                            arch_final_file.write(unprocessed)
                            arch_final_file.close()
                            arch_runs += 1
                            continue
                    else:
                        lib.PrintStatus("Making directory... ["+str(datetime.now().strftime('%X'))+"]")
                        if blacklisting is True:
                            flagged = False
                            compare_text = re.sub(r'\s+', '', unprocessed)  # strip all whitespace for comparison
                            for b in blacklist:
                                b = re.sub(r'\s+', '', b)  # strip all whitespace for comparison
                                if b.lower() in compare_text.lower():
                                    lib.PrintStatus("Blacklisted phrase detected, passing...")
                                    flagged = True

                            if flagged is True:
                                continue
                            else:
                                arch_final_file = codecs.open(str(workpath) + str(full_arch_url).replace(":", "-")
                                                              .replace(":", "-").replace("/", "-") + ".txt", 'w+',
                                                              'utf-8')
                                arch_final_file.write(unprocessed)
                                arch_final_file.close()
                                arch_runs += 1
                                continue
                        elif blacklisting is False:
                            arch_final_file = codecs.open(str(workpath) + str(full_arch_url).replace(":", "-")
                                                          .replace(":", "-").replace("/", "-") + ".txt", 'w+', 'utf-8')
                            arch_final_file.write(unprocessed)
                            arch_final_file.close()
                            arch_runs += 1
                            continue
                elif amode == 'f':
                    if path.isdir(workpath) is True:
                        lib.PrintStatus("Running engine... ["+str(datetime.now().strftime('%X'))+"]")
                        if blacklisting is True:
                            flagged = False
                            compare_text = re.sub(r'\s+', '', unprocessed)  # strip all whitespace for comparison
                            for b in blacklist:
                                b = re.sub(r'\s+', '', b)  # strip all whitespace for comparison
                                if b.lower() in compare_text.lower():
                                    lib.PrintStatus("Blacklisted phrase detected, passing...")
                                    flagged = True

                            if flagged is True:
                                continue
                            else:
                                archive_engine(unprocessed, keylisting, reglisting)
                                arch_runs += 1
                                continue
                        else:
                            lib.PrintStatus("Running engine... ["+str(datetime.now().strftime('%X'))+"]")
                            archive_engine(unprocessed, keylisting, reglisting)
                            arch_runs += 1
                            continue
        else:
            lib.PrintSuccess("Operation Finished... ["+str(datetime.now().strftime('%X'))+"]")
            break

if __name__ == "__main__":
    print("""
    _________________________________________
    [                                       ]
    [                                       ]
    [          Welcome to BinBot            ]
    [            Made by Mili               ]
    [                                       ]
    [_______________________________________]
    """)
    while True:
        configchoice = input("Load config file? [y]/[n]: ")
        if configchoice.lower() == 'y':
            configpath = input('Enter the full path of the config file: ')
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
                ArchiveSearch(stop_input, arch_mode)
            else:
                lib.PrintError("No such file found")
                continue
        elif configchoice.lower() == 'n':
            while True:
                workpath = input("Enter the path you wish to save text documents to (enter curdir for current directory): ")
                if workpath.lower() == 'curdir':
                    workpath = curdir
                if path.isdir(workpath):
                    lib.PrintSuccess("Valid Path...")
                    if workpath.endswith('\\'):
                        pass
                    else:
                        workpath = workpath + str('\\')
                    break
                else:
                    lib.PrintError("Invalid path, check input...")
                    continue

            while True:
                try:
                    stopinput_input = input("Run in a constant loop? [y]/[n]: ")
                    if stopinput_input.lower() == 'y':
                        stop_input = True
                    elif stopinput_input.lower() == 'n':
                        stop_input = int(input("Enter the amount of successful pulls you wish to make (enter 0 for infinite): "))
                    limiter = int(input("Enter the request limit you wish to use (recommended: 5): "))
                    cooldown = int(input("Enter the cooldown between IP bans/Archive scrapes (recommended: 1200): "))
                    break
                except ValueError:
                    lib.PrintError("Invalid Input.")
                    continue

            while True:
                list_choice = input("Utilize blacklisting to avoid spam documents [y]/[n]: ")
                if list_choice.lower() == 'y':
                    blacklisting = True

                    while True:
                        bfile_input = input("Read blacklisted terms from file? [y]/[n]: ")
                        if bfile_input.lower() == 'n':
                            blacklist_input = input("Enter the phrases you wish to blacklist separated by a comma: ").split(",")
                            for b in blacklist_input:
                                blacklist.append(b)
                            break
                        elif bfile_input.lower() == 'y':
                            lib.PrintStatus("File should be structured with one term per line, with no comma.")
                            bpath = input("Enter the full path of the file: ")
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

            while True:
                amode_input = input("[r]aw or [f]iltered search (filtered search will make use of the ArchiveEngine and will return fewer results): ")
                if amode_input.lower() == 'r':
                    arch_mode = 'r'
                    break
                elif amode_input.lower() == 'f':
                    arch_mode = 'f'

                    while True:
                        keychoice = input("Filter by keywords? [y]/[n]: ")
                        if keychoice not in ['y','n']:
                            lib.PrintError("Invalid Input")
                            continue
                        elif keychoice.lower() == 'y':
                            keylisting = True
                            while True:
                                filechoice = input("Load from file: [y]/[n]: ")
                                if filechoice.lower() == 'y':
                                    filterfile_input = input("Enter full path of the file: ")
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
                                    keyword_input = input(
                                        "Enter the keywords you'd like to search for, seperated by a comma: ").split(",")
                                    for k in keyword_input:
                                        key_list.append(k)
                                    break
                            break
                        elif keychoice.lower() == 'n':
                            keylisting = False
                            break
                    while True:
                        regchoice = input("Run regex matching on documents? [y]/[n]: ")
                        if regchoice not in ['y', 'n']:
                            lib.PrintError("Invalid Input")
                            continue
                        elif regchoice.lower() == 'y':
                            reglisting = True
                            while True:
                                regfilechoice = input("Load from file (one pattern per line)? [y]/[n]: ")
                                if regfilechoice.lower() not in ['y', 'n']:
                                    lib.PrintError("Invalid Input")
                                    continue
                                elif regfilechoice.lower() == 'y':
                                    while True:
                                        regpath = input(
                                            'Enter the full path (including extension) to the pattern file: ')
                                        if path.isfile(regpath) is False:
                                            lib.PrintError("No such file found.")
                                            continue
                                        else:
                                            with open(regpath, 'r') as regfile:
                                                for line in regfile.readlines():
                                                    reglist.append(line.rstrip())
                                            break
                                    break
                                elif regfilechoice.lower() == 'n':
                                    while True:
                                        reginput = input(
                                            "Enter the regex patterns separated by a comma AND a space: ").split(
                                            ', ')
                                        for pattern in reginput:
                                            reglist.append(pattern)
                                        break
                                break
                            break
                        elif regchoice.lower() == 'n':
                            reglisting = False
                            break
                    if keylisting is False and reglisting is False:
                        lib.PrintError("Both filter modes were set to false, changing search mode to raw...")
                        arch_mode = 'r'
                    break
                else:
                    lib.PrintError("Invalid Input.")
                    continue

            while True:
                savechoice = input('Save configuration to file for repeated use? [y]/[n]: ')
                if savechoice.lower() == 'n':
                    break
                elif savechoice.lower() == 'y':
                    configname = input("Enter the config name (no extension): ")
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
                        lib.PrintError(f'Error: {e}')
                        continue
                else:
                    lib.PrintError("Invalid Input")
                    continue
        else:
            lib.PrintError("Invalid Input")
            continue
        ArchiveSearch(stop_input, arch_mode)
