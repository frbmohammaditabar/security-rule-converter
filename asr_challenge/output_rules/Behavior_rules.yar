rule Rule_Behavior_txt
{
    meta:
        author = "Fariba Mohammaditabar"
        date = "2025-08-24T14:03:25.034656"
        description = "Generated from Behavior.txt"
        file_type = "text/plain"
        file_size = 953526
        md5 = "947b1e3a617de74e87af6d02236ab6bb"

    strings:
        $file_name = "Behavior.txt" wide ascii
        $hash = "947b1e3a617de74e87af6d02236ab6bb"
        
    condition:
        any of them
}
