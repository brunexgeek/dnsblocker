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

Log::Log( const char *path ) : output(nullptr), events(16 * 1024)
{
    if (path != nullptr && path[0] != 0) output = fopen(path, "wt");
    if (output == nullptr) output = stdout;
}

Log::~Log()
{
    if (output != stdout) fclose(output);
}

void Log::log( const char *format, ... )
{
    if (output == nullptr) return;

    va_list args;
    va_start(args, format);
	std::string text = Log::vaformat(false, format, args);
	va_end(args);

    std::lock_guard<std::mutex> guard(lock);
    fputs(text.c_str(), output);
    fflush(output);
}

void Log::event( const char *format, ... )
{
    if (output == nullptr) return;

    va_list args;
    va_start(args, format);
	std::string text = Log::vaformat(true, format, args);
	va_end(args);

    std::lock_guard<std::mutex> guard(lock);
    events.append(text.c_str());
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

    vsnprintf(temp, sizeof(temp), format, args);
    out += temp;
    return out;
}

void Log::print_events( webster::Message &response )
{
    std::lock_guard<std::mutex> guard(lock);

    for (auto line : events)
    {
        std::string css;
        if (line.empty())
            response.write("<p>&nbsp;</p>\n");
        else
        if (line.length() >= 3 && isdigit(line[0]) && isdigit(line[1]) && line[2] == ':')
        {
            // set the line color
            if (line.find("DE ") != std::string::npos)
                response.write("<p class='de'>");
            else
            if (line.find("NX ") != std::string::npos)
                response.write("<p class='nx'>");
            else
            if (line.find("FA ") != std::string::npos)
                response.write("<p class='fa'>");
            else
                response.write("<p>");
            // extract the domain name
            auto pos = line.rfind(' ');
            auto name = line.substr(pos+1);
            line.erase(pos+1);
            // write the line
            response.write(line);
            // write the domain name as hyperlink
            response.write("<a target='_blank' href='http://");
            response.write(name);
            response.write("'>");
            response.write(name);
            response.write("</a></p>\n");
        }
        else
        {
            response.write("<p>");
            response.write(line);
            response.write("</p>\n");
        }
    }
}

const char *Buffer::Iterator::next()
{
    // find the end of the current string
    while (*c_ != 0)
    {
        ++c_;
        if (c_ >= e_) c_ = s_;
        if (c_ == m_) return c_ = e_;
    }
    // skip the null-terminator
    ++c_;
    if (c_ >= e_) c_ = s_;
    if (*c_ == 0) c_ = e_;
    return c_;
}

std::string Buffer::Iterator::operator*() const
{
    std::string out;
    const char *ptr = c_;
    while (*ptr != 0)
    {
        out += *ptr;
        ++ptr;
        if (ptr >= e_) ptr = s_;
    }
    return out;
}

Buffer::Buffer( size_t size ) : size_(size), count_(1)
{
    if (size_ < 16) size_ = 16;
    ptr_ = new(std::nothrow) char[size_]();
    cur_ = ptr_ + 1;
}

Buffer::~Buffer()
{
    delete[] ptr_;
}

void Buffer::append( const char *value )
{
    auto len = strlen(value);
    if (len + 2 > size_) return;
    ++count_;
    if (count_ == 0) count_ = 1;

    // copy the string
    size_t count = std::min((size_t)(ptr_ + size_ - cur_), len);
    memcpy(cur_, value, count);
    if (count < len)
    {
        memcpy(ptr_, value + count, len - count);
        count = len - count;
        cur_ = ptr_;
    }
    cur_ += count;
    if (cur_ >= ptr_ + size_) cur_ = ptr_;
    // append two null-terminators (append + erase)
    append('\0');
    erase();
}

void Buffer::erase()
{
    if (*cur_ != 0)
    {
        char *p = cur_;
        while (*p != 0)
        {
            *p = 0;
            ++p;
            if (p >= ptr_ + size_) p = ptr_;
        }
    }
}

void Buffer::append( char value )
{
    *cur_ = value;
    ++cur_;
    if (cur_ >= ptr_ + size_) cur_ = ptr_;
}

void Buffer::clear()
{
    memset(ptr_, 0, size_);
    cur_ = ptr_ + 1;
}

void Buffer::dump() const
{
    for (size_t i = 0; i < size_; ++i)
    {
        if (i > 0 && (i % 8) == 0) std::cout << '\n';
        std::cout << ((ptr_ + i == cur_) ? '!' : ' ') << ((ptr_[i] == 0) ? '_' : ptr_[i]) << ' ';
    }
    std::cout << "\n\n";
}

Buffer::Iterator Buffer::begin() const
{
    const char *ptr = cur_ + 1;
    if (ptr >= ptr_ + size_) ptr = ptr_;

    while (*ptr == 0 && ptr != cur_)
    {
        ++ptr;
        if (ptr >= ptr_ + size_) ptr = ptr_;
    }
    if (ptr == cur_) return end();
    return Iterator(ptr_, ptr_+ size_, ptr);
}

Buffer::Iterator Buffer::end() const
{
    return Iterator(ptr_, ptr_+ size_, ptr_ + size_);
}
