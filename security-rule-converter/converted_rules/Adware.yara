rule Adware
{
    strings:
        $a = "fffe4100640077006100"
    condition:
        $a
}