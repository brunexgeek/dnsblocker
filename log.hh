#ifndef DNSB_LOG_HH
#define DNSB_LOG_HH


#include <stdio.h>
#include <string>
#include <mutex>


#define LOG_MESSAGE(...)    Log::instance->write(false, __VA_ARGS__)
#define LOG_TIMED(...)      Log::instance->write(true, __VA_ARGS__)


class Log
{
    public:
        static Log *instance;

        Log( const char *path );

        ~Log();

        void write( bool timed, const char *format, ... );

    private:
        FILE *output;
        std::mutex mutex;
};


#endif // DNSB_LOG_HH