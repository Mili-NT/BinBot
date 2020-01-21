rule keywords
{
    strings:
        $google_drive = "drive.google.com" wide ascii nocase
        $mega_nz = "mega.nz" wide ascii nocase
        $dropbox = "dropbox.com" wide ascii nocase
        $dropbox_direct = "dl.dropboxusercontent.com" wide ascii nocase
        $mediafire = "mediafire.com" wide ascii nocase
    condition:
        any of them

}
