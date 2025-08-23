rule Microsoft_Defender_All_signatures_list
{
    strings:
        $a = "signature,metadata_c"
    condition:
        $a
}