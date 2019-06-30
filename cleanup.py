from os import listdir, getcwd, remove
from os.path import isfile, join

curdir = getcwd()
ic = 0

print("Files generated through the raw search will begin in 'https', filtered files will begin in '['")
user_input = input("[a] to remove '[' files, [b] to remove 'https   ' files: ")
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