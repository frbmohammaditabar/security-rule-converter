rule BrowserModifier
{
    strings:
        $a = "fffe420072006f007700"
    condition:
        $a
}