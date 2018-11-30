#ifndef DNSB_LOG_HH
#define DNSB_LOG_HH


#include <stdio.h>
#include <string>


bool log_initialize( const char *path );

void log_terminate();

void log_message( const char *format, ... );

#endif // DNSB_LOG_HH