rule Rule_Backdoor_txt
{
    meta:
        author = "Fariba Mohammaditabar"
        date = "2025-08-24T14:03:25.034656"
        description = "Generated from Backdoor.txt"
        file_type = "text/plain"
        file_size = 1240170
        md5 = "114ea37447a6ce81897a45e96fdb813d"

    strings:
        $file_name = "Backdoor.txt" wide ascii
        $hash = "114ea37447a6ce81897a45e96fdb813d"
        
    condition:
        any of them
}
