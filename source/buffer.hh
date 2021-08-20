#ifndef DNSB_BUFFER_HH
#define DNSB_BUFFER_HH

#include <stdint.h>
#include <string>
#include <vector>

namespace dnsblocker {

struct buffer : public std::vector<uint8_t>
{
    uint8_t *cursor_;

    buffer( size_t size = 1024 );
    uint8_t readU8();
    uint16_t readU16();
    void writeU8( uint8_t value );
    void writeU16( uint16_t value );
    uint32_t readU32();
    void writeU32( uint32_t value );
    void reset();
    size_t remaining() const;
    size_t cursor() const;
    void skip( size_t bytes );
    std::string readQName();
    uint8_t *readLabels( uint8_t *ptr, std::string &qname );
    void writeQName( const std::string &qname);
};

}

#endif // DNSB_BUFFER_HH