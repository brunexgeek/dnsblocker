#ifndef DNSB_LOG_HH
#define DNSB_LOG_HH


#include <stdio.h>
#include <string>
#include <list>
#include <mutex>
#include <atomic>
#include "webster.hh"


#define LOG_MESSAGE(...)    Log::instance->log(__VA_ARGS__)
#define LOG_EVENT(event)    Log::instance->event(event)

struct Event
{
    uint64_t id = 0;
    uint64_t time = 0;
    std::string source;
    std::string type;
    uint8_t proto = 0;
    std::string server;
    std::string ip;
    std::string domain;
    bool heuristic = false;

    bool operator!=( const Event &that ) const
    {
        return *this != that;
    }

    bool operator==( const Event &that ) const
    {
        return
            source == that.source &&
            proto == that.proto &&
            server == that.server &&
            ip == that.ip &&
            domain == that.domain &&
            heuristic == that.heuristic;
    }


};

class EventRing
{
    public:
        typedef std::list<Event>::const_iterator Iterator;

        EventRing( size_t capacity );
        ~EventRing() = default;
        EventRing( const EventRing& );
        EventRing( EventRing&& );
        void append( const Event & );
        void append( Event && );
        void clear();
        int etag() const { return etag_; }
        size_t size() const { return entries_.size(); }
        size_t capacity() const { return max_; }
        Iterator begin() const;
        Iterator end() const;

    private:
        size_t max_ = 0;
        std::list<Event> entries_;
        int etag_ = 0;
};

class Log
{
    public:
        static Log *instance;

        Log( const char *path );
        ~Log();
        void log( const char *format, ... );
        void event( const Event& );
        EventRing get_events( uint64_t index = 0 ) const;
        void print_events( webster::Message &output );
        int etag() const { return events_.etag(); }
        static std::string format( bool timed, const char *format, ... );

    private:
        FILE *output_;
        EventRing events_;
        mutable std::mutex lock_;

        static std::string vaformat( bool timed, const char *format, va_list args );
};


#endif // DNSB_LOG_HH