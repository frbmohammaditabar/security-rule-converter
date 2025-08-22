rule sample1
{
    strings:
        $a = "This is a malicious "
    condition:
        $a
}