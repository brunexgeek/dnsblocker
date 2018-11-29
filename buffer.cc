#include "buffer.hh"


uint8_t *buffer;
uint8_t *ptr;
size_t size;
bool release;

BufferIO::BufferIO(
    size_t size ) : size(size), release(true)
{
    if (size == 0) size = 1;
    ptr = buffer = new(std::nothrow) uint8_t[size];
}

BufferIO::BufferIO(
    uint8_t *buffer,
    size_t cursor,
    size_t size ) : buffer(buffer), ptr(buffer + cursor), size(size),
        release(false)
{
}

BufferIO::~BufferIO()
{
    if (release) delete[] buffer;
}

uint16_t BufferIO::readU16()
{
    uint16_t value = static_cast<uint16_t>(ptr[0] << 8);
    value = (uint16_t) (value + static_cast<uint16_t>(ptr[1]));
    ptr += sizeof(uint16_t);
    return value;
}

void BufferIO::writeU16( uint16_t value )
{
    ptr[0] = (uint8_t) ((value & 0xFF00) >> 8);
    ptr[1] = (uint8_t) (value & 0xFF);
    ptr += sizeof(uint16_t);
}

uint32_t BufferIO::readU32()
{
    uint32_t value = (uint32_t) (ptr[0] << 24);
    value = (uint32_t) (value + (uint32_t) (ptr[1] << 16) );
    value = (uint32_t) (value + (uint32_t) (ptr[2] << 8) );
    value = (uint32_t) (value + (uint32_t) ptr[3] );
    ptr += sizeof(uint32_t);
    return value;
}

void BufferIO::writeU32( uint32_t value )
{
    ptr[0] = (uint8_t) ((value & 0xFF000000) >> 24);
    ptr[1] = (uint8_t) ((value & 0x00FF0000) >> 16);
    ptr[2] = (uint8_t) ((value & 0x0000FF00) >> 8);
    ptr[3] = (uint8_t) ((value & 0x000000FF));
    ptr += sizeof(uint32_t);
}

void BufferIO::reset()
{
    ptr = buffer;
}

size_t BufferIO::remaining() const
{
    return size - (size_t)(ptr - buffer);
}

size_t BufferIO::cursor() const
{
    return (size_t)(ptr - buffer);
}

void BufferIO::skip( size_t bytes )
{
    ptr += bytes;
}

std::string BufferIO::readQName()
{
    std::string qname;

    // check whether the qname is a pointer (RFC-1035 4.1.4. Message compression)
    if ((*ptr & 0xC0) == 0xC0)
    {
        size_t offset = ((ptr[0] & 0x3F) << 8) | ptr[1];
        uint8_t *prev = ptr + 2;
        ptr = buffer + offset;
        std::string temp = readQName();
        ptr = prev;
        return temp;
    }

    int length = *ptr++;
    while (length != 0)
    {
        for (int i = 0; i < length; i++)
        {
            char c = *ptr++;
            qname.append(1, c);
        }
        length = *ptr++;
        if (length != 0) qname.append(1,'.');
    }

    return qname;
}

void BufferIO::writeQName( const std::string &qname)
{
    size_t start(0), end; // indexes

    while ((end = qname.find('.', start)) != std::string::npos)
    {
        *ptr++ = (uint8_t) (end - start); // label length octet
        for (size_t i=start; i<end; i++) {

            *ptr++ = qname[i]; // label octets
        }
        start = end + 1; // ignore dots
    }

    *ptr++ = (uint8_t) (qname.size() - start); // last label length octet
    for (size_t i=start; i<qname.size(); i++) {

        *ptr++ = qname[i]; // last label octets
    }

    *ptr++ = 0;
}