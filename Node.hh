#include <stdint.h>
#include <iostream>
#include <string>

struct Node
{
    Node *slots[26 + 10 + 2]; // 26 letters, 10 digits, dash and dot
    bool isTerminal = false; // this node is a terminal symbol
    bool isStar = false; // denote a wildcard
    int id = 0;
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
