# BinBot
BinBot is a script designed to monitor the public archive of text documents from the site pastebin.
By utilizing YARA pattern matching, BinBot is capable of:
* Detecting common indicators of malware
* Applying sets of regular expressions to documents
* Blacklisting documents that are not of interest
* Searching for keywords or phrases in documents
## YARA Rules:
To add YARA rules, simply place the .yar or .yara file in `yara_rules/general_rules` 
to be ran on text files or `yara_rules/binary_rules` to be ran on executable files.

Make sure to customize your `blacklist.yar` and `keywords.yar` file. 

## Usage:
`python3 BinBot.py <path to configuration file>`

If no path is passed, binbot will run a manual setup.
## Planned Features:
* Logging system


## Planned Features and TODO:
- API integration

