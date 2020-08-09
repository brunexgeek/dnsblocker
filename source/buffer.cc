#include "buffer.hh"

namespace dnsblocker {

buffer::buffer( size_t size ) : std::vector<uint8_t>(size)
{
    cursor_ = data();
}

uint16_t buffer::readU16()
{
    uint16_t value = static_cast<uint16_t>(cursor_[0] << 8) | static_cast<uint16_t>(cursor_[1]);
    cursor_ += sizeof(uint16_t);
    return value;
}

void buffer::writeU16( uint16_t value )
{
    cursor_[0] = (uint8_t) (value >> 8);
    cursor_[1] = (uint8_t) value;
    cursor_ += sizeof(uint16_t);
}

uint32_t buffer::readU32()
{
    uint32_t value = (uint32_t) ( (cursor_[0] << 24) | (cursor_[1] << 16) | (cursor_[2] << 8) | cursor_[3] );
    cursor_ += sizeof(uint32_t);
    return value;
}

void buffer::writeU32( uint32_t value )
{
    cursor_[0] = (uint8_t) (value >> 24);
    cursor_[1] = (uint8_t) (value >> 16);
    cursor_[2] = (uint8_t) (value >> 8);
    cursor_[3] = (uint8_t) value;
    cursor_ += sizeof(uint32_t);
}

void buffer::reset()
{
    cursor_ = data();
}

size_t buffer::remaining() const
{
    return size() - (size_t) (cursor_ - data());
}

size_t buffer::cursor() const
{
    return (size_t) (cursor_ - data());
}

void buffer::skip( size_t bytes )
{
    cursor_ += bytes;
}

// TODO: include bound checking
uint8_t *buffer::readLabels( uint8_t *ptr, std::string &qname )
{
    uint8_t *buffer = data();
    if (ptr < buffer || ptr >= buffer + size()) return nullptr;

    while (*ptr != 0)
    {
        // check whether the label is a pointer (RFC-1035 4.1.4. Message compression)
        if ((*ptr & 0xC0) == 0xC0)
        {
            size_t offset = ((ptr[0] & 0x3F) << 8) | ptr[1];
            readLabels(buffer + offset, qname);
            return ptr += 2;
        }

        int length = (int) (*ptr++) & 0x3F;
        for (int i = 0; i < length; ++i)
        {
            char c = (char) *ptr++;
            if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            qname.push_back(c);
        }

        if (*ptr != 0) qname.push_back('.');
    }

    return ptr + 1;
}


std::string buffer::readQName()
{
    std::string qname;
    cursor_ = readLabels(cursor_, qname);
    return qname;
}

void buffer::writeQName( const std::string &qname)
{
    size_t start = 0, end; // indexes

    while ((end = qname.find('.', start)) != std::string::npos)
    {
        *cursor_++ = (uint8_t) (end - start); // label length octet
        for (size_t i=start; i<end; i++)
        {
            char c = qname[i];
            if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            *cursor_++ = c; // label octets
        }
        start = end + 1; // ignore dots
    }

    *cursor_++ = (uint8_t) (qname.size() - start); // last label length octet
    for (size_t i = start; i < qname.size(); i++)
    {
        *cursor_++ = qname[i]; // last label octets
    }

    *cursor_++ = 0;
}

}
