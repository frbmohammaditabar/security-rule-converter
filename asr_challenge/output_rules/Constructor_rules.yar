rule Rule_Constructor_txt
{
    meta:
        author = "Fariba Mohammaditabar"
        date = "2025-08-24T14:03:25.034656"
        description = "Generated from Constructor.txt"
        file_type = "text/plain"
        file_size = 35412
        md5 = "c4fca59d11ede11cc01ec1d5297afc29"

    strings:
        $file_name = "Constructor.txt" wide ascii
        $hash = "c4fca59d11ede11cc01ec1d5297afc29"
        
    condition:
        any of them
}
