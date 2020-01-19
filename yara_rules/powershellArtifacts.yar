/*
This replaces the pre-yara default powershell dict
*/
rule powershellArtifacts
{
    strings:
        $a1 = "powershell" fullword wide ascii nocase
        $a2 = "downloadstring" fullword wide ascii nocase
        $a3 = "-WindowStyle Hidden" fullword wide ascii nocase
        $a4 = "-exec Bypass" fullword wide ascii nocase
        $a5 = "IEX" fullword wide ascii nocase
        $a6 = "Invoke-" fullword wide ascii nocase
        $a7 = "FromBase64String(" fullword wide ascii nocase
        $a8 = "new-object" fullword wide ascii nocase
        $a9 = "webclient" fullword wide ascii nocase
        $a10 = "Set-ExecutionPolicy" fullword wide ascii nocase
        $a11 = "certutil -decode" fullword wide ascii nocase
        $a12 = "hidden" fullword wide ascii nocase
        $a13 = "nop" fullword wide ascii nocase
        $a14 = "EmpireProject" fullword wide ascii nocase
        $a15 = "PowershellEmpire" fullword wide ascii nocase
        $a16 = "Nishang" fullword wide ascii nocase

    condition:
        2 of ($a*)

}
