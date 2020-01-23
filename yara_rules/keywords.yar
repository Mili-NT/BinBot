rule keywords
{
    strings:
        $google_drive = "drive.google.com" wide ascii nocase
        $mega_nz = "mega.nz" wide ascii nocase
        $pastebin = "pastebin.com" wide ascii nocase
        $pastebin_raw = "pastebin.com/raw" wide ascii nocase
        $mediafire = "mediafire.com" wide ascii nocase
        $sha256 = "sha256" wide ascii nocase
        $rawgithub = "raw.githubusercontent.com" wide ascii nocase
    condition:
        any of them

}
