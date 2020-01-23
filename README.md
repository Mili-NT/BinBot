# BinBot
BinBot is a script designed to monitor the public archive of text documents from the site pastebin.
By utilizing YARA pattern matching, BinBot is capable of:
* Detecting common indicators of malware
* Applying sets of regular expressions to documents
* Blacklisting documents that are not of interest
* Searching for keywords or phrases in documents

To add YARA rules, simply place your rule.yar file in the yara_rules folder.
Make sure to customize your blacklist.yar and keywords.yar file. By defualt the blacklist filters:
* minecraft crash logs
* iptv playlists
* serfish/ssh bitcoin scams
* chegg links

The keywords are:
* drive.google.com
* mega.nz
* pastebin.com
* pastebin.com/raw

## Planned Features:

* pastebin API support (WORK IN PROGRESS)
* Logging system
* Malware file hash identification


## TODO:
- Fix b64 matches not being saved as .b64 files
- Fix blacklisted files still saving when they match other rules
