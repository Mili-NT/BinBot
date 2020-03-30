rule keywords
{
    strings:
        $mega_nz = "mega.nz" wide ascii nocase
        $mediafire = "mediafire.com" wide ascii nocase
        $anonfile = "anonfile.com"
        $zippyshare = "zippyshare.com"
        $uploadfiles = "uploadfiles.io"
        $ghostbin = "ghostbin.com"
        $throwbin = "throwbin.com"
        $raidforums = "raidforums" wide ascii nocase
    condition:
        any of them

}

