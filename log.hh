#ifndef DNSB_LOG_HH
#define DNSB_LOG_HH


#include <stdio.h>


bool log_initialize( bool toFile = true );

void log_terminate();

void log_message( const char *format, ... );

#endif // DNSB_LOG_HH