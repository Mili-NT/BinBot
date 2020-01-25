 rule blacklist
{
    strings:
        $b1 = "EXTINF:" nocase
        $b2 = "EXTM3U" nocase
        $b3 = "chegg" nocase
        $b4 = "bukkit" nocase
        $b5 = "Minecraft" nocase
        $b6 = "serfish" nocase
        $b7 = "Technic Launcher is starting" nocase
        $b8 = "[Server Thread/WARN]" nocase
        $b9 = "SimC Addon"
        $b10 = "M3U" nocase
    condition:
        any of them

}
