#ifndef DNSB_LOG_HH
#define DNSB_LOG_HH


#include <stdio.h>
#include <string>
#include <mutex>
#include "webster.hh"


#define LOG_MESSAGE(...)    Log::instance->log(__VA_ARGS__)
#define LOG_EVENT(...)      Log::instance->event(__VA_ARGS__)

class Buffer
{
    public:
        class Iterator
        {
            public:
                using iterator_category = std::input_iterator_tag;
                using difference_type   = std::ptrdiff_t;
                using value_type        = char;
                using pointer           = const char*;
                using reference         = const char&;

                Iterator(pointer s, pointer e, pointer c) : s_(s), e_(e), c_(c), m_(c) {}
                std::string operator*() const;
                pointer operator->() const { return c_; }
                Iterator& operator++() { next(); return *this; }
                Iterator operator++(int) { Iterator tmp = *this; next(); return tmp; }
                friend bool operator== (const Iterator& a, const Iterator& b) { return a.c_ == b.c_; };
                friend bool operator!= (const Iterator& a, const Iterator& b) { return a.c_ != b.c_; };
                pointer next();

            private:
                pointer s_;
                pointer e_;
                pointer c_;
                pointer m_;
        };

        Buffer( size_t size );
        Buffer( const Buffer &that );
        Buffer( Buffer &&that );
        virtual ~Buffer();
        void append( const char *value );
        void erase();
        void clear();
        void dump() const;
        int etag() const { return count_; }
        Iterator begin() const;
        Iterator end() const;

    private:
        char *ptr_;
        size_t size_;
        char *cur_;
        uint32_t count_;

        void append( char value );
};

class Log
{
    public:
        static Log *instance;

        Log( const char *path );

        ~Log();

        void log( const char *format, ... );
        void event( const char *format, ... );
        Buffer get_events() const;
        void print_events( webster::Message &output );
        int etag() const { return events.etag(); }
        static std::string format( bool timed, const char *format, ... );

    private:
        FILE *output;
        Buffer events;
        mutable std::mutex lock;

        static std::string vaformat( bool timed, const char *format, va_list args );
};


#endif // DNSB_LOG_HH