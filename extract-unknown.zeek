@load base/files/extract

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    # If Zeek fails to identify a MIME type, force the file to extract it
    if ( ! meta?$mime_type )
        {
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
        }
    }