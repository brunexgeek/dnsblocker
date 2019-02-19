#ifndef DNSB_NODES_HH
#define DNSB_NODES_HH

#include <stdint.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include "log.hh"


int charToIndex( char c );
char indexToChar( int index );
char *prepareHostname( char *host );


template<typename T>
struct Node
{
    static const uint16_t TERMINAL = 1; // this node is a terminal symbol
    static const uint16_t WILDCARD = 2; // denote a wildcard
    static const int SLOTS    = 38; // 26 letters, 10 digits, dash and dot
    static const int MAX_HOST_LENGTH = 512;

    uint16_t slots[SLOTS];
    uint16_t flags = 0;
    T value;

    Node();
    ~Node();
};



template<typename T>
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
        bool add( const std::string &target, T value );
        const Node<T> *match( const std::string &host ) const;

    private:
        Node<T> *root;
        std::vector< Node<T> > nodes;
};


template<typename T>
Node<T>::Node()
{
    memset(slots, 0, sizeof(slots));
    flags = 0;
}


template<typename T>
Node<T>::~Node()
{
}


template<typename T>
Tree<T>::Tree()
{
    nodes.resize(1);
    root = &nodes.front();
}


template<typename T>
Tree<T>::~Tree()
{
}


template<typename T>
bool Tree<T>::load(
    const std::string &fileName )
{
    std::ifstream rules(fileName.c_str());
    if (rules.good())
    {
        std::string line;

        while (!rules.eof())
        {
            std::getline(rules, line);
            if (line.empty()) continue;

            // we have a comment?
            const char *ptr = line.c_str();
            while (*ptr == ' ') ++ptr;
            if (*ptr == '#') continue;

            if (add(line, 0))
            {
                LOG_MESSAGE("  Added '%s'\n", line.c_str());
            }
            else
                LOG_MESSAGE("  Invalid rule '%s'\n", line.c_str());
        }

        rules.close();
        return true;
    }

    return false;
}


template<typename T>
uint32_t Tree<T>::size() const
{
    return (uint32_t) nodes.size();
}


template<typename T>
size_t Tree<T>::memory() const
{
    return sizeof(Node<T>) * nodes.size() + sizeof(Tree<T>);
}


template<typename T>
bool Tree<T>::add( const std::string &target, T value )
{
    if (target.empty() || target.length() > Node<T>::MAX_HOST_LENGTH) return false;

    char temp[Node<T>::MAX_HOST_LENGTH + 1] = { 0 };
    strcpy(temp, target.c_str());

    bool isWildcard = false;
    // '*' and '**' must precede a period
    if (temp[0] == '*')
    {
        isWildcard = true;

        // if we have a 'double star', add the domain itself
        if (temp[1] == '*' && temp[2] == '.')
            add(temp + 3, value);
        else
        if (temp[1] != '.')
            return false;
    }

    // preprocess the host name
    char *ptr = prepareHostname(temp);
    if (ptr == nullptr) return false;

    uint16_t current = 0;
    #define CURRENT  (nodes[current])

    for (;*ptr != 0; ++ptr)
    {
        int idx = charToIndex(*ptr);
        if (CURRENT.slots[idx] == 0)
        {
            nodes.resize(nodes.size() + 1);
            uint16_t temp = (uint16_t) (nodes.size() - 1);
            CURRENT.slots[idx] = temp;
            current = temp;
        }
        else
        {
            current = CURRENT.slots[idx];
            if (CURRENT.flags & Node<T>::WILDCARD) return false;
        }
    }
    CURRENT.flags |= Node<T>::TERMINAL;
    CURRENT.value = value;
    if (isWildcard) CURRENT.flags |= Node<T>::WILDCARD;

    #undef CURRENT

    return true;
}


template<typename T>
const Node<T> *Tree<T>::match( const std::string &target ) const
{
    if (target.empty() || target.length() > Node<T>::MAX_HOST_LENGTH) return nullptr;

    char temp[Node<T>::MAX_HOST_LENGTH + 1] = { 0 };
    strcpy(temp, target.c_str());

    // preprocess the host name
    char *ptr = prepareHostname(temp);
    if (ptr == nullptr) return nullptr;

    uint16_t current = 0;
    #define CURRENT  (nodes[current])

    for (;*ptr != 0; ++ptr)
    {
        if (CURRENT.flags & Node<T>::WILDCARD) return &CURRENT;

        int idx = charToIndex(*ptr);
        current = CURRENT.slots[idx];
        if (current == 0) return nullptr;
    }

    if ((CURRENT.flags & Node<T>::TERMINAL) != 0)
        return &CURRENT;
    else
        return nullptr;

    #undef CURRENT
}


#endif // DNSB_NODES_HH