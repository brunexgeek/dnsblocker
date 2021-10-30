#ifndef DNSB_LOG_HH
#define DNSB_LOG_HH


#include <stdio.h>
#include <string>
#include <mutex>


#define LOG_MESSAGE(...)    Log::instance->write(false, __VA_ARGS__)
#define LOG_TIMED(...)      Log::instance->write(true, __VA_ARGS__)

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
        virtual ~Buffer();
        void append( const char *value );
        void clear();
        void dump() const;
        Iterator begin() const;
        Iterator end() const;

    private:
        char *ptr_;
        size_t size_;
        char *cur_;

        void append( char value );
};

class Log
{
    public:
        static Log *instance;

        Log( const char *path );

        ~Log();

        void write( bool timed, const char *format, ... );

    private:
        FILE *output;
        std::mutex lock;
};


#endif // DNSB_LOG_HH