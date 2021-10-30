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

const char *Buffer::Iterator::next()
{
    std::cout << "next()\n";
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

Buffer::Buffer( size_t size ) : size_(size)
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
    if (len + 1 >= size_) return;
    for (const char *c = value; *c != 0; ++c) append(*c);
    append('\0');

    if (*cur_ != 0)
    {
        // remove the string being corrupted
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
