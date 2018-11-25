#include <stdint.h>
#include <string>
#include <vector>


#define DNS_GET_QR(x)         ((x) & 15)
#define DNS_GET_OPCODE(x)     (((x) >> 11) & 15)
#define DNS_GET_AA(x)         ((x) & 10)  // Authoritative Answer
#define DNS_GET_TC(x)         ((x) &  9)  // message TrunCation
#define DNS_GET_RD(x)         ((x) &  8)  // Recursion Desired
#define DNS_GET_RA(x)         ((x) &  7)  // Recursion Available
#define DNS_GET_Z(x)          ((x) &  6)  // reserved for future use
#define DNS_GET_AD(x)         ((x) &  5)  // Authentic Data
#define DNS_GET_CD(x)         ((x) &  4)  // Checking Disabled
#define DNS_GET_RCODE(x)      ((x) & 15)  // Response Code

#define DNS_SET_QR(x)           ( x |= 1 << 15)
#define DNS_SET_OPCODE(x,v)     ( x |= ( (v) & 15 ) << 11)
#define DNS_SET_AA(x)           ( x |= 1 << 10)
#define DNS_SET_TC(x)           ( x |= 1 <<  9)
#define DNS_SET_RD(x)           ( x |= 1 <<  8)
#define DNS_SET_RA(x)           ( x |= 1 <<  7)
#define DNS_SET_Z(x)            ( x |= 1 <<  6)
#define DNS_SET_AD(x)           ( x |= 1 <<  5)
#define DNS_SET_CD(x)           ( x |= 1 <<  4)
#define DNS_SET_RCODE(x,v)      ( x |= ( (v) & 15 ))

static const uint16_t DNS_TYPE_A      = 1;
static const uint16_t DNS_TYPE_NS     = 2;
static const uint16_t DNS_TYPE_CNAME  = 5;
static const uint16_t DNS_TYPE_PTR    = 12;
static const uint16_t DNS_TYPE_MX     = 15;
static const uint16_t DNS_TYPE_TXT    = 16;

struct dns_header_t
{
    uint16_t id;
    uint16_t fields;
    uint16_t qdcount; // query count
    uint16_t ancount; // answer count
    uint16_t nscount; // name server count
    uint16_t arcount; // additional record count

    dns_header_t();
};

struct dns_question_t
{
    std::string qname;
    uint16_t type;
    uint16_t clazz;

    dns_question_t();
    dns_question_t( const dns_question_t &obj );
};

struct dns_record_t
{
    std::string qname;
    uint16_t type;
    uint16_t clazz;
    uint32_t ttl;
    //uint16_t rdlen;
    //std::string rdata;

    dns_record_t();
};

struct dns_message_t
{
    dns_header_t header;
    std::vector<dns_question_t> questions;
    std::vector<dns_record_t> answers;
};


struct BufferIO
{
    uint8_t *buffer;
    uint8_t *ptr;
    size_t size;

    BufferIO(
        uint8_t *buffer,
        size_t cursor,
        size_t size ) : buffer(buffer), ptr(buffer + cursor), size(size)
    {
    }

    uint16_t readU16()
    {
        uint16_t value = static_cast<uint16_t>(ptr[0] << 8);
        value = (uint16_t) (value + static_cast<uint16_t>(ptr[1]));
        ptr += sizeof(uint16_t);
        return value;
    }

    void writeU16( uint16_t value )
    {
        ptr[0] = (uint8_t) ((value & 0xFF00) >> 8);
        ptr[1] = (uint8_t) (value & 0xFF);
        ptr += sizeof(uint16_t);
    }

    void writeU32( uint32_t value )
    {
        ptr[0] = (uint8_t) ((value & 0xFF000000) >> 24);
        ptr[1] = (uint8_t) ((value & 0x00FF0000) >> 16);
        ptr[2] = (uint8_t) ((value & 0x0000FF00) >> 8);
        ptr[3] = (uint8_t) ((value & 0x000000FF));
        ptr += sizeof(uint32_t);
    }

    void reset()
    {
        ptr = buffer;
    }

    size_t remaining() const
    {
        return size - (size_t)(ptr - buffer);
    }

    size_t cursor() const
    {
        return (size_t)(ptr - buffer);
    }

    std::string readQName()
    {
        std::string qname;

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

    void writeQName( const std::string &qname)
    {
        size_t start(0), end; // indexes

        while ((end = qname.find('.', start)) != std::string::npos) {

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
};


void dns_decode(
    BufferIO &bio,
    dns_message_t &message );

void dns_encode(
    BufferIO &bio,
    dns_message_t &message );

bool dns_recursive(
    uint8_t *buffer,
    size_t size,
    size_t *cursor );