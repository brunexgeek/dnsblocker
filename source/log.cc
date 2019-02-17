#include "log.hh"
#include "defs.hh"
#include <time.h>
#include <stdarg.h>
#include <limits.h>
#include <cstdlib>
#include <string>

Log *Log::instance = nullptr;

Log::Log( const char *path ) : output(nullptr)
{
    if (path != nullptr && path[0] != 0) output = fopen(path, "wt");
    if (output == nullptr) output = stdout;
}

Log::~Log()
{
    if (output != stdout) fclose(output);
}


void Log::write(
    bool timed,
    const char *format,
    ... )
{
    if (output == nullptr) return;

    std::lock_guard<std::mutex> raii(lock);

    if (timed)
    {
        time_t rawtime;
        struct tm timeinfo;
        char timeStr[12] = { 0 };

        time(&rawtime);
		#ifdef __WINDOWS__
		localtime_s(&timeinfo, &rawtime);
		#else
        localtime_r(&rawtime, &timeinfo);
		#endif
        strftime(timeStr, sizeof(timeStr) - 1, "%H:%M:%S", &timeinfo);
        fprintf(output, "%s  ", timeStr);
    }

    va_list args;
    va_start(args, format);
	vfprintf(output, format, args);
	va_end(args);
	fflush(output);
}