rule keywords
{
    strings:
        $google_drive = "drive.google.com" wide ascii nocase
        $mega_nz = "mega.nz" wide ascii nocase
        $mediafire = "mediafire.com" wide ascii nocase
        $rawgithub = "raw.githubusercontent.com" wide ascii nocase
        $magnet = "magnet:?xt=urn:"
        $ghostbin = "ghostbin.com"
        $throwbin = "throwbin.com"
    condition:
        any of them

}
