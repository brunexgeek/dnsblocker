#ifndef DNSB_BUFFER_HH
#define DNSB_BUFFER_HH


#include <stdint.h>
#include <string>


struct BufferIO
{
    uint8_t *buffer;
    uint8_t *ptr;
    size_t size;
    bool release;

    BufferIO(
        size_t size );

    BufferIO(
        uint8_t *buffer,
        size_t cursor,
        size_t size );

    ~BufferIO();

    uint16_t readU16();

    void writeU16( uint16_t value );

    uint32_t readU32();

    void writeU32( uint32_t value );

    void reset();

    size_t remaining() const;

    size_t cursor() const;

    void skip( size_t bytes );

    std::string readQName();

    static uint8_t *readLabels( uint8_t *buffer, uint8_t *ptr, std::string &qname );

    void writeQName( const std::string &qname);

};


#endif // DNSB_BUFFER_HH