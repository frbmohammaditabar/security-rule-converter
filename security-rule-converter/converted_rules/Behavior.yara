rule Behavior
{
    strings:
        $a = "fffe4200650068006100"
    condition:
        $a
}