# BinBot
BinBot is a script designed to aggregate data from multiple *bin sources, and flexibly classify and sort 
that data using YARA rules.
## YARA Rules:
By utilizing YARA pattern matching, BinBot is capable of:
* Detecting common indicators of malware
* Applying sets of regular expressions to documents
* Blacklisting documents that are not of interest
* Searching for keywords or phrases in documents

To add YARA rules, simply place the .yar or .yara file in `yara_rules/general_rules` 
to be ran on text files or `yara_rules/binary_rules` to be ran on executable files.

Make sure to customize your `blacklist.yar` and `keywords.yar` file. 
## Currently Supported Services:
* [Pastebin](https://pastebin.com/)
* [ix.io](http://ix.io/)
* [slexy](https://slexy.org/)
## Usage:
`python3 BinBot.py <path to configuration file>`

If no path is passed, binbot will run a manual setup.
## Credits:
* Binary rules found [here](https://github.com/InQuest/awesome-yara#rules) 
and credited individually in the rule files.
* KindredSec's [pastebin video](https://www.youtube.com/watch?v=y5OObEOWuDY) 
was an inspiration for the base64 rules
* [r/learnpython](https://www.reddit.com/r/learnpython/), as always
## Planned Features and TODO:
- Fix error in service multithreading that causes runs to immediately end

