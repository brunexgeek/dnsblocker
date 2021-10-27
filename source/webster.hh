/*
 *   Copyright 2020 Bruno Ribeiro
 *   <https://github.com/brunexgeek/webster>
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#ifndef WEBSTER_API_HH
#define WEBSTER_API_HH

#if defined(_MSC_VER) || defined(WIN32) || defined(_WIN32)
#define WEBSTER_PRIVATE
#define WB_WINDOWS 1
#else
#define WEBSTER_PRIVATE __attribute__((__visibility__("hidden")))
#endif

#include <stdint.h>
#include <stddef.h>
#include <functional>
#include <string>
#include <type_traits>

/// Operation completed with success.
const int WBERR_OK                   = 0;
const int WBERR_INVALID_ARGUMENT     = -1;
const int WBERR_MEMORY_EXHAUSTED     = -2;
const int WBERR_INVALID_ADDRESS      = -3;
const int WBERR_SOCKET               = -4;
/// The communication was completed with success and the connection will be closed.
const int WBERR_COMPLETE             = -6;
const int WBERR_TOO_LONG             = -7;
const int WBERR_TIMEOUT              = -11;
const int WBERR_INVALID_STATE        = -12;
const int WBERR_INVALID_HTTP_METHOD  = -14;
const int WBERR_INVALID_HTTP_VERSION = -16;
const int WBERR_INVALID_HTTP_MESSAGE = -17;
const int WBERR_INVALID_TARGET       = -18;
const int WBERR_INVALID_SCHEME       = -19;
const int WBERR_INVALID_HOST         = -20;
const int WBERR_INVALID_PORT         = -21;
const int WBERR_INVALID_CHANNEL      = -22;
const int WBERR_REFUSED              = -23;
const int WBERR_UNREACHABLE          = -24;
const int WBERR_IN_PROGRESS          = -25;
const int WBERR_ADDRESS_IN_USE       = -27;
const int WBERR_INVALID_CHUNK        = -28;
const int WBERR_NOT_CONNECTED        = -29;
const int WBERR_SIGNAL               = -30;
const int WBERR_INVALID_HTTP_FIELD   = -32;
const int WBERR_PERMISSION           = -31;
const int WBERR_INVALID_HANDLER      = -33;
const int WBERR_NOT_IMPLEMENTED      = -34;
const int WBERR_NO_RESOURCES         = -35;
const int WBERR_ALREADY_CONNECTED    = -36;
const int WBERR_INVALID_PROTOCOL     = -37;
const int WBERR_UPGRADED             = -38;
const int WBERR_READ_ONLY            = -39;
const int WBERR_WRITE_ONLY           = -40;

/**
 * HTTP header field identifier.
 */
enum FieldID
{
    WBFI_NON_STANDARD = 0,
    WBFI_ACCEPT,
    WBFI_ACCEPT_CHARSET,
    WBFI_ACCEPT_ENCODING,
    WBFI_ACCEPT_LANGUAGE,
    WBFI_ACCEPT_PATCH,
    WBFI_ACCEPT_RANGES,
    WBFI_ACCESS_CONTROL_ALLOW_CREDENTIALS,
    WBFI_ACCESS_CONTROL_ALLOW_HEADERS,
    WBFI_ACCESS_CONTROL_ALLOW_METHODS,
    WBFI_ACCESS_CONTROL_ALLOW_ORIGIN,
    WBFI_ACCESS_CONTROL_EXPOSE_HEADERS,
    WBFI_ACCESS_CONTROL_MAX_AGE,
    WBFI_ACCESS_CONTROL_REQUEST_HEADERS,
    WBFI_ACCESS_CONTROL_REQUEST_METHOD,
    WBFI_AGE, // RFC-7234
    WBFI_ALLOW,
    WBFI_ALT_SVC,
    WBFI_AUTHORIZATION,
    WBFI_CACHE_CONTROL,
    WBFI_CONNECTION,
    WBFI_CONTENT_DISPOSITION,
    WBFI_CONTENT_ENCODING,
    WBFI_CONTENT_LANGUAGE,
    WBFI_CONTENT_LENGTH,
    WBFI_CONTENT_LOCATION,
    WBFI_CONTENT_RANGE,
    WBFI_CONTENT_TYPE,
    WBFI_COOKIE,
    WBFI_DATE,
    WBFI_DNT,
    WBFI_ETAG,
    WBFI_EXPECT,
    WBFI_EXPIRES,
    WBFI_FORWARDED,
    WBFI_FROM,
    WBFI_HOST,
    WBFI_IF_MATCH,
    WBFI_IF_MODIFIED_SINCE,
    WBFI_IF_NONE_MATCH,
    WBFI_IF_RANGE,
    WBFI_IF_UNMODIFIED_SINCE,
    WBFI_LAST_MODIFIED,
    WBFI_LINK,
    WBFI_LOCATION,
    WBFI_MAX_FORWARDS,
    WBFI_ORIGIN,
    WBFI_PRAGMA,
    WBFI_PROXY_AUTHENTICATE,
    WBFI_PROXY_AUTHORIZATION,
    WBFI_PUBLIC_KEY_PINS,
    WBFI_RANGE,
    WBFI_REFERER,
    WBFI_RETRY_AFTER,
    WBFI_SERVER,
    WBFI_SET_COOKIE,
    WBFI_STRICT_TRANSPORT_SECURITY,
    WBFI_TE,
    WBFI_TK,
    WBFI_TRAILER,
    WBFI_TRANSFER_ENCODING,
    WBFI_UPGRADE,
    WBFI_UPGRADE_INSECURE_REQUESTS,
    WBFI_USER_AGENT,
    WBFI_VARY,
    WBFI_VIA,
    WBFI_WARNING,
    WBFI_WWW_AUTHENTICATE,
};

// Request target types

const int WBRT_ORIGIN    = 0x01;
const int WBRT_AUTHORITY = 0x02;
const int WBRT_ABSOLUTE  = (WBRT_ORIGIN + 0x04 + WBRT_AUTHORITY);
const int WBRT_ASTERISK  = 0x08;

// Schemas

const int WBS_AUTO       = 0;
const int WBS_HTTP       = 1;
const int WBS_HTTPS      = 2;

// Limits

const int WBL_MIN_BUFFER_SIZE = 64;
const int WBL_MAX_BUFFER_SIZE = 10485760; // 10 MB
const int WBL_DEF_BUFFER_SIZE = 4096; // 4KB
const int WBL_MAX_CONNECTIONS = 10000;
const int WBL_DEF_CONNECTIONS = 200;
const int WBL_DEF_TIMEOUT     = 10000; // 10 sec
const int WBL_MAX_TIMEOUT     = 620000; // 10 minutes

#include <memory>
#include <map>
#include <string>
#include <vector>
#include <stdint.h>

namespace webster {

WEBSTER_PRIVATE uint64_t tick();
WEBSTER_PRIVATE int strcmpi(const char *s1, const char *s2);

struct Target
{
    int type;
    int scheme;
    std::string user;
    std::string host;
    int port;
    std::string path;
    std::string query;

    Target();
    Target( const Target & ) = default;
    Target( Target && ) = default;
    Target &operator=( const Target & ) = default;
    static int parse( const char *url, Target &target ); // TODO: make this dynamic
    static int parse( const std::string &url, Target &target ); // TODO: make this dynamic
    static std::string encode( const std::string & value );
    static std::string decode( const std::string & value );
    void swap( Target &that );
    void clear();
};

class Channel {};

/**
 * Abstraction for network adapters.
 */
class Network
{
    public:
        enum Type { CLIENT, SERVER };
        /**
         * Create a channel.
         *
         * @returns WBERR_OK on success; error code otherwise.
         */
        virtual int open( Channel **channel, Type type ) = 0;
        /**
         * Close and destroy a channel.
         *
         * @returns WBERR_OK on success; error code otherwise.
         */
        virtual int close( Channel *channel ) = 0;
        /**
         * Connect to a HTTP server.
         *
         * @returns WBERR_OK on success; error code otherwise.
         */
        virtual int connect( Channel *channel, int scheme, const char *host, int port, int timeout ) = 0;
        /**
         * Receive data.
         *
         * @param channel Pointer to the channel.
         * @param buffer Pointer to the destination buffer.
         * @param size Buffer size.
         * @param received Pointer to store the amount of data retrieved.
         * @param timeout Aproximated number of milliseconds the function will block
         *    waiting for data.
         * @returns WBERR_OK on success; error code otherwise.
         */
        virtual int receive( Channel *channel, uint8_t *buffer, int size, int *received, int timeout ) = 0;
        /**
         * Write data.
         *
         * This function will succeed only if all data is written.
         *
         * @param channel Pointer to the channel.
         * @param buffer Pointer to the destination buffer.
         * @param size Buffer size.
         * @param timeout Aproximated number of milliseconds the function will block
         *    writing data.
         * @returns WBERR_OK on success; error code otherwise.
         */
        virtual int send( Channel *channel, const uint8_t *buffer, int size, int timeout ) = 0;
        /**
         * Accept client connections.
         *
         * This function will return if interrupted by signals.
         *
         * @param channel Pointer to the channel.
         * @param channel Pointer to the new channel.
         * @param timeout Aproximated number of milliseconds the function will block
         *    waiting for connections.
         */
        virtual int accept( Channel *channel, Channel **client, int timeout ) = 0;
        virtual int listen( Channel *channel, const char *host, int port, int maxClients ) = 0;
};

struct Parameters
{
    /**
     * Pointer to custom network implementation.
     *
     * Set to 'nullptr' to use the default implementation. Note that the default
     * implementation is not available if 'WEBSTER_NO_DEFAULT_NETWORK' is set.
     */
    std::shared_ptr<Network> network;

    /**
     * Maximum number of remote clients in the server queue. The default value is
     * WBL_DEF_CONNECTIONS.
     */
    int max_clients;

    /**
     * Size (in bytes) of the message internal output buffer. The default value
     * is WBL_DEF_BUFFER_SIZE.
     */
    int buffer_size;

    /**
     * Read timeout in milliseconds (between 1 and ``WBL_MAX_TIMEOUT``).
     */
    int read_timeout;

    /**
     * Write timeout in milliseconds (between 1 and ``WBL_MAX_TIMEOUT``).
     */
    int write_timeout;

    /**
     * Connection timeout in milliseconds (between 1 and ``WBL_MAX_TIMEOUT``).
     */
    int connect_timeout;

    Parameters();
    Parameters( const Parameters &that );
    Parameters &operator=( const Parameters &that );
};

enum Protocol
{
    WBCP_NONE,  // No protocol
    WBCP_HTTP_1 // HTTP 1.1
};

enum ClientType
{
    /// Client used to connect to a remote host.
    WBCT_LOCAL,
    /// Client trying to connect the server.
    WBCT_REMOTE,
};

class Client;
class Server;

enum Method
{
    WBM_NONE    = 0,
    WBM_GET     = 1,
    WBM_HEAD    = 2,
    WBM_POST    = 3,
    WBM_PUT     = 4,
    WBM_DELETE  = 5,
    WBM_CONNECT = 6,
    WBM_OPTIONS = 7,
    WBM_TRACE   = 8,
    WBM_PATCH   = 9,
};

struct less
{
    typedef std::string first_argument_type;
    typedef std::string second_argument_type;
    typedef bool result_type;

    bool operator() (const std::string& x, const std::string& y) const
    {
        return strcmpi(x.c_str(), y.c_str()) < 0;
    }
};

class HeaderFields : public std::map<std::string, std::string, webster::less>
{
    public:
        using std::map<std::string, std::string, webster::less>::count;
        std::string get( const std::string &name )  const;
        std::string get( FieldID id )  const;
        std::string get( const std::string &name, const std::string &value )  const;
        std::string get( FieldID id, const std::string &value )  const;
        template<typename T, typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
        T get( const std::string &name, T value )  const
        {
            auto it = find(name);
            if (it == end()) return value;
            return (T) strtol(it->second.c_str(), nullptr, 10);
        }
        template<typename T, typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
        T get( FieldID id, T value ) const
        {
            return get(get_name(id), value);
        }
        void set( const std::string &name, const std::string &value );
        void set( FieldID id, const std::string &value );
        template<typename T, typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
        void set( const std::string &name, T value )
        {
            set(name, std::to_string(value));
        }
        template<typename T, typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
        void set( FieldID id, T value )
        {
            set(get_name(id), std::to_string(value));
        }
        size_t count( FieldID id ) const;
        static const char *get_name( FieldID id );
};

struct Header
{
    Target target;
    int status;
    HeaderFields fields;
    Method method;

    Header();
    Header( const Header & ) = default;
    Header( Header && ) = default;
    Header &operator=( const Header & ) = default;
    void swap( Header &that );
    void clear();
};

class Message
{
    public:
        Header header;
        virtual ~Message() = default;
        /**
         * Try to read bytes from the message.
         *
         * @param buffer Pointer to destination buffer .
         * @param size Buffer size.
         * @returns Positive number of bytes read or a negative error code.
         */
        virtual int read( uint8_t *buffer, int size ) = 0;
        /**
         * Try to read bytes from the message.
         *
         * This function may read less bytes than requested.
         *
         * Although the buffer is a 'char' array, this function reads data
         * as binary. Thus, the output buffer may contain null characters.
         *
         * The output buffer is guaranteed to have a null terminator after
         * a successfully call.
         *
         * @param buffer Pointer to destination buffer .
         * @param size Buffer size.
         * @returns Positive number of bytes read or a negative error code.
         */
        virtual int read( char *buffer, int size ) = 0;
        /**
         * Read the remaining data to a 'std::vector<uint8>' object.
         *
         * @param buffer Vector object to store the data.
         * @returns WBERR_OK if succeed or a negative error code.
         */
        virtual int read_all( std::vector<uint8_t> &buffer ) = 0;
        /**
         * Read the remaining data to a 'std::string' object.
         *
         * Although the buffer is a string object, this function reads data
         * as binary. Thus, the output buffer may contain null characters.
         *
         * @param buffer String object to store the data.
         * @returns WBERR_OK if succeed or a negative error code.
         */
        virtual int read_all( std::string &buffer ) = 0;
        virtual int write( const uint8_t *buffer, int size ) = 0;
        virtual int write( const char *buffer ) = 0;
        virtual int write( const std::string &buffer ) = 0;
        virtual int write( const std::vector<uint8_t> &buffer ) = 0;
        template<typename T, typename std::enable_if<std::is_integral<T>::value, bool>::type = true>
        int write( const T &value )
        {
            return write(std::to_string(value));
        }
        /**
         * Wait until the message body is ready to be read or written.
         *
         * This function will block the execution until the message body is ready.
         * The amount of time the function waits is the read or write timeout,
         * depending on the message type (incomming or outgoing).
         *
         * For incomming messages, the HTTP header will be completely received.
         * For outgoing messages, this function will force the HTTP header to be sent.
         */
        virtual int ready() = 0;
        /**
         * Send all buffered data of the outgoing message.
         *
         * By default, every write call is buffered and no data is sent until
         * the buffer is full. This function force the current buffer content
         * be sent.
         *
         * This function will force the HTTP header to be sent.
         */
        virtual int flush() = 0;
        /**
         * Finish the message by discarding or writing necessary data.
         *
         * For incomming messages, this function discard all incomming body data
         * until the end of the message.
         *
         * For outgoing messages, this function write any necessary data and
         * complete the message. No more data can be written after this call.
         */
        virtual int finish() = 0;

        Message &operator<<( const std::string &value )
        {
            write(value);
            return *this;
        }
        Message &operator<<( const char &value )
        {
            write(value);
            return *this;
        }
        template<typename T, typename std::enable_if<std::is_integral<T>::value, bool>::type = true>
        Message &operator<<( const T &value )
        {
            write(value);
            return *this;
        }
};

class HttpListener
{
    public:
        HttpListener() = default;
        HttpListener( const HttpListener & ) = default;
        HttpListener( HttpListener && ) = default;
        HttpListener( std::function<int(Message&,Message&)> );
        HttpListener( int (&func)(Message&,Message&) );
        /**
         * Perform an HTTP comunication between client and server.
         *
         * For local clients, the listener must generate a request and process the response.
         * For remote clients, the listener must process the request and generate a response.
         *
         * @param request Request messages.
         * @param response Response messages.
         * @return WBERR_OK or WBERR_COMPLETE in case of success. An error code otherwhise.
         */
        virtual int operator()(Message &request, Message &response);
    protected:
        std::function<int(Message&,Message&)> func_;
};

class HttpServer;

class HttpClient
{
    public:
        HttpClient( ClientType type = WBCT_LOCAL, Client *client = nullptr );
        ~HttpClient();
        /**
         * Connect to a remote host.
         *
         * @param url URL to the remote host.
         * @param params Network parameters.
         * @return WBERR_OK in case of success. An error code otherwhise.
         */
        int open( const char *url, const Parameters &params = Parameters() );
        /**
         * Connect to a remote host.
         *
         * @param url URL to the remote host.
         * @param params Network parameters.
         * @return WBERR_OK in case of success. An error code otherwhise.
         */
        int open( const Target &url, const Parameters &params = Parameters() );
        /**
         * Close the connection with the HTTP server.
         *
         * @return WBERR_OK in case of success. An error code otherwhise.
         */
        int close();
        /**
         * Perform an HTTP comunication between client and server.
         *
         * If this is a local client, the listener must generate a request and process the response.
         * If this is a remote client, the listener must process the request and generate a response.
         *
         * The path to the resource is obtained from the connection URL.
         *
         * @param listener Listener to process the messages.
         * @return WBERR_OK or WBERR_COMPLETE in case of success. An error code otherwhise.
         */
        int communicate( HttpListener &listener );
        /**
         * Perform an HTTP comunication between client and server.
         *
         * If this is a local client, the listener must generate a request and process the response.
         * If this is a remote client, the listener must process the request and generate a response.
         *
         * @param path Path to the resource.
         * @param listener Listener to process the messages.
         * @return WBERR_OK or WBERR_COMPLETE in case of success. An error code otherwhise.
         */
        int communicate( const std::string &path, HttpListener &listener );
        /**
         * Returns the protocol implemented by the client.
         *
         * @return Protocol code.
         */
        Protocol get_protocol() const;
        /**
         * Returns the pointer to the internal client object.
         *
         * @return Pointer to client object. If the client is not connected, returns nullptr.
         */
        Client *get_client();
        /**
         * Returns the client type;
         *
         * @returns WBCT_LOCAL for local client or WBCT_REMOTE for remote client.
         */
        ClientType get_type() const;

    protected:
        Client *client_;
        Protocol proto_;
        ClientType type_;

        int communicate_local( const std::string &path, HttpListener &listener );
        int communicate_remote( HttpListener &listener );
};

class HttpServer
{
    public:
        HttpServer();
        HttpServer( Parameters params );
        ~HttpServer();
        int start( const Target &target );
        int start( const std::string &target );
        int stop();
        int accept( HttpClient **remote );
        const Parameters &get_parameters() const;
        const Target &get_target() const;
    protected:
        Server *server_;
};

} // namespace webster

#endif // WEBSTER_API_HH
