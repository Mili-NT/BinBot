#!/usr/bin/python3
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
import sys
import random


def main(runs):
    files = [f"{os.getcwd()}/{f}" for f in os.listdir(os.getcwd()) if os.path.isfile(f)]
    for _ in range(int(runs)):
        os.system(f"nano {random.choice(files)}")

if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except IndexError:
        print(f"Usage: {sys.argv[0]} <runs>")
