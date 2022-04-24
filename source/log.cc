#include "log.hh"
#include "defs.hh"
#include <time.h>
#include <stdarg.h>
#include <limits.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <iomanip>

Log *Log::instance = nullptr;

Log::Log( const char *path ) : output_(nullptr), events_(16 * 1024)
{
    if (path != nullptr && path[0] != 0) output_ = fopen(path, "wt");
    if (output_ == nullptr) output_ = stdout;
}

Log::~Log()
{
    if (output_ != stdout) fclose(output_);
}

void Log::log( const char *format, ... )
{
    if (output_ == nullptr) return;

    va_list args;
    va_start(args, format);
	std::string text = Log::vaformat(false, format, args);
	va_end(args);

    std::lock_guard<std::mutex> guard(lock_);
    fputs(text.c_str(), output_);
    fflush(output_);
}

void Log::event( const Event &event )
{
    std::lock_guard<std::mutex> guard(lock_);
    events_.append(event);
}

std::string Log::format( bool timed, const char *format, ... )
{
    std::string out;

    va_list args;
    va_start(args, format);
	out += vaformat(timed, format, args);
	va_end(args);

    return out;
}

std::string Log::vaformat(
    bool timed,
    const char *format,
    va_list args )
{
    std::string out;
    char temp[256] = { 0 };

    if (timed)
    {
        time_t rawtime;
        struct tm timeinfo;

        time(&rawtime);
		#ifdef __WINDOWS__
		localtime_s(&timeinfo, &rawtime);
		#else
        localtime_r(&rawtime, &timeinfo);
		#endif
        strftime(temp, sizeof(temp) - 1, "%H:%M:%S", &timeinfo);
        out += temp;
        out += ' ';
    }

    vsnprintf(temp, sizeof(temp) - 1, format, args);
    //auto last = strlen(temp);
    //while (last > 0 && (temp[last] == 0 || temp[last] == '\n'))
    //    temp[last--] = 0;
    out += temp;
    return out;
}

EventRing Log::get_events( uint64_t id ) const
{
    std::lock_guard<std::mutex> guard(lock_);

    if (id == 0)
        return EventRing(events_);
    else
    {
        EventRing temp(events_.size());
        auto it = events_.begin();
        while (it != events_.end() && it->id < id)
            ++it;
        while (it != events_.end())
        {
            temp.append(*it);
            ++it;
        }
        return temp;
    }
}

EventRing::EventRing( size_t capacity ) : max_(capacity)
{
}

EventRing::EventRing( const EventRing &that ) : max_(that.max_), entries_(that.entries_)
{
}

EventRing::EventRing( EventRing &&that ) : max_(that.max_)
{
    entries_.swap(that.entries_);
}

void EventRing::append( const Event &value )
{
    bool append = !(entries_.size() > 0 && entries_.back() == value);
    if (append)
    {
        if (entries_.size() >= max_)
            entries_.pop_front();
        entries_.push_back(value);
        ++etag_;
    }
}

void EventRing::append( Event &&value )
{
    if (entries_.size() >= max_)
        entries_.pop_front();
    entries_.push_back(std::move(value));
    ++etag_;
}

void EventRing::clear()
{
    entries_.clear();
}

EventRing::Iterator EventRing::begin() const
{
    return entries_.cbegin();
}

EventRing::Iterator EventRing::end() const
{
    return entries_.cend();
}
