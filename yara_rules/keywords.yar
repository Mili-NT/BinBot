rule keywords
{
    strings:
        $google_drive = "drive.google.com" wide ascii nocase
        $mega_nz = "mega.nz" wide ascii nocase
        $dropbox = "dropbox.com" wide ascii nocase
        $dropbox_dl = "dl.dropboxusercontent.com" wide ascii nocase
        $mediafire = "mediafire.com" wide ascii nocase
        $sha256 = "sha265" wide ascii nocase
    condition:
        any of them

}
