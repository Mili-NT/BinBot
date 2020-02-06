/*
This replaces the pre-yara default b64 dict. Now with 100% less tupling.
Most of the positional file strings I learned from KindredSec's pastebin video:
https://www.youtube.com/watch?v=y5OObEOWuDY

b64PE regular expression found here:
https://isc.sans.edu/forums/diary/Searching+for+Base64encoded+PE+Files/22199/
*/

rule b64PE
{
    strings:
        $b64PE = /\bTV(oA|pB|pQ|qA|qQ|ro)/
    condition:
        $b64PE at 0

}

rule b64ELF
{
    strings:
        $b64ELF = "f0VM"
    condition:
        $b64ELF at 0
}

rule b64Zip
{
    strings:
        $b64Zip = "UEs"
    condition:
        $b64Zip at 0

}

rule b64Gz
{
    strings:
        $b64Gz = "H4sI"
    condition:
        $b64Gz at 0

}

