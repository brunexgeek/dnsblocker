#include "log.hh"
#include "config.hh"
#include <time.h>
#include <stdarg.h>
#include <limits.h>
#include <cstdlib>
#include <string>


static FILE *LOG_FILE = nullptr;

bool log_initialize( const char *path )
{
    if (path == nullptr || path[0] == 0)
    {
        LOG_FILE = stdout;
        return true;
    }
    else
    {
        LOG_FILE = fopen(path, "wt");
        return (LOG_FILE != nullptr);
    }
}

void log_terminate()
{
    #ifdef ENABLE_DAEMON
    if (LOG_FILE != nullptr) fclose(LOG_FILE);
    #endif
}


void log_message(
    const char *format,
    ... )
{
    if (LOG_FILE == nullptr) return;

    #ifdef ENABLE_TIMESTAMP
    time_t rawtime;
	struct tm timeinfo;
	char timeStr[24] = { 0 };

    time(&rawtime);
	localtime_r(&rawtime, &timeinfo);
	strftime(timeStr, sizeof(timeStr) - 1, "%d/%m/%Y %H:%M:%S", &timeinfo);
	fprintf(LOG_FILE, "%s  ", timeStr);
    #endif

    va_list args;
    va_start(args, format);
	vfprintf(LOG_FILE, format, args);
	va_end(args);
	fflush(LOG_FILE);
}