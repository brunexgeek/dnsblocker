#include "log.hh"
#include "config.hh"
#include <time.h>
#include <stdarg.h>


static FILE *LOG_FILE = nullptr;

bool log_initialize( bool toFile )
{
    if (toFile)
    {
        LOG_FILE = fopen(LOG_FILENAME, "wt");
        return (LOG_FILE != nullptr);
    }
    else
    {
        LOG_FILE = stdout;
        return true;
    }
}

void log_terminate()
{
    #ifdef ENABLE_DAEMON
    fclose(LOG_FILE);
    #endif
}


void log_message(
    const char *format,
    ... )
{
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