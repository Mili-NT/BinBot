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
import requests
from random import choice
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
    return { 'User-Agent': choice(user_agents), 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' }
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


