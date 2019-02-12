#include <stdint.h>
#include <iostream>
#include "log.hh"

//#define NODE_ENABLE_ID 1

struct Node
{
    static const int TERMINAL = 1; // this node is a terminal symbol
    static const int WILDCARD = 2; // denote a wildcard
    static const int SLOTS    = 38; // 26 letters, 10 digits, dash and dot
    static const int MAX_HOST_LENGTH = 512;

    Node *slots[SLOTS];
    int flags = 0;
    #ifdef NODE_ENABLE_ID
    uint id = 0;
    #endif

    Node();
    ~Node();
    int index( char c ) const;
    char text( int index );
    char *prepare( char *host ) const;
    bool add( const std::string &host, uint32_t id, size_t *allocated = nullptr );
    bool match( const std::string &host ) const;
    #ifdef NODE_ENABLE_ID
    void print( std::ostream &out );
    #endif
};



class Tree
{
    public:
        Tree();
        ~Tree();
        Tree( const Tree &that ) = delete;
        Tree( Tree &&that ) = delete;
        bool load( const std::string &fileName );
        uint32_t size() const;
        size_t memory() const;
        bool add( const std::string &host, uint32_t id );
        bool match( const std::string &host ) const;

    private:
        Node root;
        uint32_t counter;
        size_t allocated;
};

