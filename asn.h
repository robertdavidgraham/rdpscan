
/* asn.c */
RD_BOOL ber_in_header(STREAM s, int *tagval, int *length);
void ber_out_header(STREAM s, int tagval, int length);
RD_BOOL ber_parse_header(STREAM s, int tagval, int *length);
void ber_out_integer(STREAM s, int value);
