#include <stdint.h>
#include <iostream>
#include <string>


struct Node
{
    static const int TERMINAL = 1; // this node is a terminal symbol
    static const int WILDCARD = 2; // denote a wildcard

    Node *slots[26 + 10 + 2]; // 26 letters, 10 digits, dash and dot
    int flags = 0;
    uint id = 0;
    static size_t allocated;
    static int counter;

    Node();

    static int nextId();

    int index( char c );

    char text( int index );

    bool convert( const std::string &host, std::string &entry );

    bool add( const std::string &host );

    bool match( const std::string &host );

    void print( std::ostream &out );

    static bool load( const std::string &fileName, Node &root );

    static int count();

};
