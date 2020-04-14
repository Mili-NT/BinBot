/*
    Credit: https://github.com/airbnb/binaryalert/blob/master/rules/public/hacktool/windows/
    Assembled from multiple mimikatz rules from listed source
*/
rule windows_mimikatz
{
    meta:
        description = "Mimikatz credential dump tool"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        SHA256_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        SHA256_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
    strings:
        $s1 = "dpapisrv!g_MasterKeyCacheList" fullword ascii wide
        $s2 = "lsasrv!g_MasterKeyCacheList" fullword ascii wide
        $s3 = "!SspCredentialList" ascii wide
        $s4 = "livessp!LiveGlobalLogonSessionList" fullword ascii wide
        $s5 = "wdigest!l_LogSessList" fullword ascii wide
        $s6 = "tspkg!TSGlobalCredTable" fullword ascii wide
        $s7 = "Kiwi en C" fullword ascii wide
        $s8 = "Benjamin DELPY `gentilkiwi`" fullword ascii wide
        $s9 = "http://blog.gentilkiwi.com/mimikatz" fullword ascii wide
        $s10 = "Build with love for POC only" fullword ascii wide
        $s11 = "gentilkiwi (Benjamin DELPY)" fullword wide
        $s12 = "KiwiSSP" fullword wide
        $s13 = "Kiwi Security Support Provider" fullword wide
        $s14 = "kiwi flavor !" fullword wide
        $s15 = "[ERROR] [LSA] Symbols" fullword ascii wide
        $s16 = "[ERROR] [CRYPTO] Acquire keys" fullword ascii wide
        $s17 = "[ERROR] [CRYPTO] Symbols" fullword ascii wide
        $s18 = "[ERROR] [CRYPTO] Init" fullword ascii wide
        $s19 = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%" wide ascii
        $s20 = "0123456789012345678901234567890123456789" wide ascii
        $s21 = "NTPASSWORD" wide ascii
        $s22 = "LMPASSWORD" wide ascii
        $s23 = "aad3b435b51404eeaad3b435b51404ee" wide ascii
        $s24 = "31d6cfe0d16ae931b73c59d7e0c089c0" wide ascii
        $s25 = "kiwifilter.log" fullword wide
        $s26 = "kiwissp.log" fullword wide
        $s27 = "mimilib.dll" fullword ascii wide
    condition:
        2 of ($s*)
}
