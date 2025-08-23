rule Dialer
{
    strings:
        $a = "fffe4400690061006c00"
    condition:
        $a
}