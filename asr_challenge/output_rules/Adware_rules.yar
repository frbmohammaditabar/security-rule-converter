rule Rule_Adware_txt
{
    meta:
        author = "Fariba Mohammaditabar"
        date = "2025-08-24T14:03:25.034656"
        description = "Generated from Adware.txt"
        file_type = "text/plain"
        file_size = 95012
        md5 = "4cd54dbb372c7b8c80226602d028a48a"

    strings:
        $file_name = "Adware.txt" wide ascii
        $hash = "4cd54dbb372c7b8c80226602d028a48a"
        
    condition:
        any of them
}
