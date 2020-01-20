 rule blacklist
{
    strings:
        $b1 = "#EXTINF:" nocase
        $b2 = "#EXTM3U" nocase
        $b3 = "chegg" nocase
        $b4 = "bukkit" nocase
        $b5 = "Minecraft" nocase
        $b6 = "serfish" nocase
        $b7 = "Technic Launcher is starting"
        $b8 = "[Server Thread/WARN]"
    condition:
        any of them

}