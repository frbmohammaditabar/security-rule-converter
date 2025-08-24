rule Rule_Dialer_txt
{
    meta:
        author = "Fariba Mohammaditabar"
        date = "2025-08-24T14:03:25.034656"
        description = "Generated from Dialer.txt"
        file_type = "text/plain"
        file_size = 8244
        md5 = "edb34733aae0a0a808b4dd68ed188688"

    strings:
        $file_name = "Dialer.txt" wide ascii
        $hash = "edb34733aae0a0a808b4dd68ed188688"
        
    condition:
        any of them
}
