# BinBot
BinBot is a script designed to monitor the public archive of text documents from the site pastebin.
By utilizing YARA pattern matching, BinBot is capable of:
* Detecting common indicators of malware
* Applying sets of regular expressions to documents
* Blacklisting documents that are not of interest
* Searching for keywords or phrases in documents

To add YARA rules, simply place the rules to be ran on default pastes in the general_rules folder.
Any rules you want ran on executable files, place in the binary_rules folder.
Make sure to customize your blacklist.yar and keywords.yar file. 

## Planned Features:
* Logging system
* External services API integration (VT & HybridAnalysis)


## TODO:
- Fix base64 gzipped pastes not being decompressed and renamed
