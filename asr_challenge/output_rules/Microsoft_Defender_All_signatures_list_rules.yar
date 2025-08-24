rule CSV_Rule_Microsoft_Defender_All_signatures_list_csv
{
    meta:
        author = "Fariba Mohammaditabar"
        date = "2025-08-24T14:03:25.034656"
        description = "Basic rule for CSV file: Microsoft_Defender_All_signatures_list.csv"
        file_type = "text/csv"

    strings:
        $file_name = "Microsoft_Defender_All_signatures_list.csv" wide ascii
        $hash = "90e8fda9e5eb35844e1ff93f1f1d63ef"
        
    condition:
        any of them
}
