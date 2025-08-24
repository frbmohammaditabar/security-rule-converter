rule Rule_BrowserModifier_txt
{
    meta:
        author = "Fariba Mohammaditabar"
        date = "2025-08-24T14:03:25.034656"
        description = "Generated from BrowserModifier.txt"
        file_type = "text/plain"
        file_size = 47888
        md5 = "33383444cd156b6d7bc5ec8b74e49d2c"

    strings:
        $file_name = "BrowserModifier.txt" wide ascii
        $hash = "33383444cd156b6d7bc5ec8b74e49d2c"
        
    condition:
        any of them
}
