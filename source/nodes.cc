#include "nodes.hh"
#include <cstring>
#include <fstream>
#include "log.hh"


int charToIndex( char c )
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A'; // 0..25
    if (c >= 'a' && c <= 'z')
        return c - 'a'; // 0..25
    if (c >= '0' && c <= '9')
        return c - '0' + 26; // 26..35
    if (c == '-')
        return 36;
    if (c == '.')
        return 37;
    return -1;
}

char indexToChar( int index )
{
    if (index >= 0 && index <= 25) return (char)('A' + index);
    if (index >= 26 && index <= 35) return (char)('0' + index);
    if (index == 36) return '-';
    if (index == 37) return '.';
    return '?';
}

char *prepareHostname( char *host )
{
    if (host == nullptr) return nullptr;
    char *ptr = host;

    // remove leading and trailing unused characters
    while (*ptr == ' ' || *ptr == '*') ++ptr;
    if (*ptr == 0) return nullptr;
    for (size_t i = strlen(ptr) - 1; ptr[i] == ' '; --i) *ptr = 0;
    // validate the host characters
    for (char *p = ptr; *p != 0; ++p)
        if (charToIndex(*p) < 0) return nullptr;
    // reverse the symbols
    for (size_t i = 0, t = strlen(ptr); i < t / 2; i++)
        std::swap(ptr[i],  ptr[t - i - 1]);

    if (*ptr == '.') return nullptr;

    return ptr;
}


