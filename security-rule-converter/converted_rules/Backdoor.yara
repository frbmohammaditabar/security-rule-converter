rule Backdoor
{
    strings:
        $a = "fffe57006f0072006d00"
    condition:
        $a
}