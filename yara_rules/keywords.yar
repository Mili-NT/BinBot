rule keywords
{
    strings:
        $google_drive = "drive.google.com" wide ascii nocase
        $mega_nz = "mega.nz" wide ascii nocase
        $mediafire = "mediafire.com" wide ascii nocase
        $rawgithub = "raw.githubusercontent.com" wide ascii nocase
        $anonfile = "anonfile.com"
        $zippyshare = "zippyshare.com"
        $uploadfiles = "uploadfiles.io"
        $ghostbin = "ghostbin.com"
        $throwbin = "throwbin.com"
    condition:
        any of them

}
