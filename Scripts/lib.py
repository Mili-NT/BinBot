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
import socket
import requests
from random import choice

UserAgents = [
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

def PrintSuccess(Msg):
    if os.name == 'nt':
        print('[+] ' + Msg)
    else:
        print('\033[1;32m[+]\033[1;m ' + Msg)

def PrintStatus(Msg):
    if os.name == 'nt':
        print('[*] ' + Msg)
    else:
        print('\033[1;34m[*]\033[1;m ' + Msg)

def PrintFailure(Msg):
    if os.name == 'nt':
        print('[-] ' + Msg)
    else:
        print('\033[1;31m[-]\033[1;m ' + Msg)

def PrintError(Msg):
    if os.name == 'nt':
        print('[!] ' + Msg)
    else:
        print('\033[1;31m[!]\033[1;m ' + Msg)

def IsIPAddress(Address):
    try:
        socket.inet_aton(Address)
        if Address.count('.') == 3:
            return True
    except socket.error:
        return False

def ValidateIP(Address):
    AddressChunks = Address.split('.')
    if len(AddressChunks) != 4:
        return False
    for Chunk in AddressChunks:
        if not Chunk.isdigit():
            return False
        ChunkInt = int(Chunk)
        if ChunkInt < 0 or ChunkInt > 255:
            return False
    return True

def RandomHeaders():
    return { 'User-Agent': choice(UserAgents), 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' }
