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

from os import listdir, getcwd, remove
from os.path import isfile, join

curdir = getcwd()
ic = 0

print("Files generated through the raw search will begin in 'https', filtered files will begin in '['")
user_input = input("[a] to remove '[' files, [b] to remove 'https' files: ")
dirinput = input("Enter the path you wish to save text documents to (enter curdir for current directory): ")
if dirinput.endswith('\\'):
    pass
else:
    dirinput = dirinput + "\\"

onlyfiles = [f for f in listdir(dirinput) if isfile(join(dirinput, f))]
for i in onlyfiles:
    if user_input == 'b':
        if i.startswith('http'):
            remove(dirinput + i)
            ic += 1
            print(ic)
        else:
            pass
    else:
        if i.startswith('['):
            remove(dirinput + i)
            ic += 1
            print(ic)
        else:
            pass
