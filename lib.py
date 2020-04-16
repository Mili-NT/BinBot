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

import os
import gzip
import codecs
import requests
from random import choice
from zipfile import ZipFile
from base64 import b64decode
from bs4 import BeautifulSoup
from datetime import datetime

#
# Requests Utility Functions:
#
user_agents = [
	'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14',
	'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36',
	'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36',
	'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0'
]
def random_proxies():
    """
    :return: a dict with a single key:value pair: {schema:address}. For example, {'http':127.0.0.1}
    """
    # Connect to the free proxy list and parse the html
    prox_url = 'https://free-proxy-list.net/'
    prox = requests.get(prox_url)
    soup = BeautifulSoup(prox.text, 'html.parser')
    # Find the table and parse it into a list of schema://address elements
    table = soup.find('table', attrs={'class': "table table-striped table-bordered"})
    proxies = [f"{'http://' if element[6].text == 'no' else 'https://'}{element[0].text}:{element[1].text}" for element in [tr.find_all("td") for tr in table.find_all("tr")] if element]
    # select a random element and parse it into the dict
    selected = choice(proxies)
    return {f"{selected.split(':')[0]}":selected}
def random_headers():
    return {'User-Agent': choice(user_agents), 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'}
#
# Printing Functions:
#
"""
These functions provide a wrapper around print() for easy terminal output.
They take the string to be printed as the msg parameter, and calls print() on the formatted string.
In the case of print_input, it returns an input() object

Format: {symbol} [{time}]: {msg}
Only difference between OS is linux has bash color code support in the format.
"""
def print_success(msg):
    if os.name == "nt":
        print(f"[+] {msg}")
    else:
        print(f"\033[1;32m[+]\033[1;m [{datetime.now().strftime('%X')}] {msg}")
def print_status(msg):
    if os.name == "nt":
        print(f"[*] {msg}")
    else:
        print(f"\033[1;34m[*]\033[1;m [{datetime.now().strftime('%X')}] {msg}")
def print_failure(msg):
    if os.name == "nt":
        print(f"[-] {msg}")
    else:
        print(f"\033[1;31m[-]\033[1;m [{datetime.now().strftime('%X')}] {msg}")
def print_error(msg):
    if os.name == "nt":
        print(f"[!] {msg}")
    else:
        print(f"\033[1;31m[!]\033[1;m [{datetime.now().strftime('%X')}] {msg}")
def print_input(msg):
    if os.name == "nt":
        return input(f"[?] {msg}: ")
    else:
        return input(f"\033[1;33m[*]\033[1;m {msg}: ")
def print_title(msg):
    if os.name == "nt":
        print(msg)
    else:
        print(f"\033[35m {msg}")
#
# YARA Functions:
#
def binary_matching(vars_dict, filepath):
    """
    :param vars_dict: The dictionary of variables returned from config()
    :param filepath: the filepath of the file to scan
    :return: Nothing
    """
    matches = vars_dict['binary_rules'].match(data=codecs.open(filepath, 'rb', 'utf-8'))
    if matches:
        components = {'rule': matches[0].rule,
                      'term': ((matches[0]).strings[0])[2] if isinstance(((matches[0]).strings[0])[2], str) else
                      ((matches[0]).strings[0])[2].decode('UTF-8'),
                      'id': (((matches[0]).strings[0])[1])[1:]}
        print_success(f"{os.path.split(filepath)[1]} matches for {components['rule']}")
        print_success(f"Matched item: {components['term']}")
        os.rename(filepath, f"{os.path.split(filepath)[0]}/{components['rule']}.file")
def general_matching(vars_dict, prescan_text, proch, components):
    """
    :param vars_dict: The dictionary of variables returned from config()
    :param prescan_text: The text parsed from the paste
    :param proch: The URL parameter of the individual paste
    :param components: The rule, term, and id of the match
    :return: Nothing
    """
    if components['rule'] == 'b64Artifacts':
        print_success(f"Base64 Artifact Found: [{components['term']}]")
        # If gzipped, decompress:
        if components['term'] == "H4sI":
            filename = f"{vars_dict['workpath']}{proch}.file"
            codecs.open(filename, 'w+', 'utf-8').write(gzip.decompress(bytes(b64decode(prescan_text), 'utf-8')))
        # Otherwise, decode and save:
        else:
            filename = f"{vars_dict['workpath']}{components['id']}_{proch}.txt"
            codecs.open(filename, 'w+', 'utf-8').write(b64decode(prescan_text))
        # If zipped, unzip and pass all files in unzipped directory to binary_matching
        if components['rule'] == "UEs":
            zip_dir = f"{vars_dict['workpath']}/{os.path.split(filename)[1].split('.')[0]}"
            ZipFile(filename, "r").extractall(zip_dir)
            for file in [os.path.join(vars_dict['workpath'], f) for f in os.listdir(zip_dir)]:
                binary_matching(vars_dict, file)
        # If not zipped, pass the singular file to binary_matching
        else:
            binary_matching(vars_dict, filename)
    elif components['rule'] == 'powershellArtifacts':
        print_success(f"Powershell Artifact Found: [{components['term']}]")
        codecs.open(f"{vars_dict['workpath']}{components['term']}_{proch}.ps1", 'w+', 'utf-8').write(prescan_text)
    elif components['rule'] == 'keywords':
        print_success(f"Keyword found: [{components['term']}]")
        codecs.open(f"{vars_dict['workpath']}{components['term']}_{proch}.txt", 'w+', 'utf-8').write(prescan_text)
    elif components['rule'] == 'regex_pattern':
        print_success(f"{components['rule']} match found: {components['id']}")
        codecs.open(f"{vars_dict['workpath']}{components['id']}_{proch}.txt", 'w+', 'utf-8').write(prescan_text)
    # Custom rules will be saved by this statement:
    else:
        print_success(f"{components['rule']} match found: {components['term']}")
        codecs.open(f"{vars_dict['workpath']}{components['id']}_{proch}.txt", 'w+', 'utf-8').write(prescan_text)
def archive_engine(prescan_text, identifier, vars_dict): # This is the matching function, very important
    """
    This function scans files for YARA matches (if enabled) and saves files.

    :param prescan_text: The raw text of the paste
    :param identifier: The URL parameter of the paste (i.e: https://pastebin.com/{proch})
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
                print_status(f"Blacklisted term detected: [{components['term']}]")
            # Otherwise, continue checking rules
            else:
                general_matching(vars_dict, prescan_text, identifier, components)
        #If no matches are found, it just writes it with the parameter as a name
        else:
            print_status(f"No matches in document: /{identifier}")
            codecs.open(f"{vars_dict['workpath']}{identifier}.txt", 'w+', 'utf-8').write(prescan_text)
    else:
        codecs.open(f"{vars_dict['workpath']}{identifier}.txt", 'w+', "utf-8").write(prescan_text)
#
# Misc Program Functions:
#
def connect(url):
    """
    :param url: address to connect to
    :return: Response object for the page connected to
    """
    try:
        return requests.get(url, headers=random_headers())
    except Exception as e:
        print_error(e)
