#ifndef PROTOGEN_2_0_0
#define PROTOGEN_2_0_0

#include <string>
#include <vector>
#include <iostream>
#include <forward_list>
#include <istream>
#include <iterator>
#include <memory>

#define PG_MKSTR(...) #__VA_ARGS__

namespace protogen_2_0_0 {

enum error_code
{
    PGERR_OK                = 0,
    PGERR_IGNORE_FAILED     = 1,
    PGERR_MISSING_FIELD     = 2,
    PGERR_INVALID_SEPARATOR = 3,
    PGERR_INVALID_VALUE     = 4,
    PGERR_INVALID_OBJECT    = 5,
    PGERR_INVALID_NAME      = 6,
};

enum parse_error
{
    PGR_OK,
    PGR_ERROR,
    PGR_NIL,
};

struct ErrorInfo : public std::exception
{
    error_code code;
    std::string message;
    int line, column;

    ErrorInfo() : code(error_code::PGERR_OK), line(0), column(0) {};
    ErrorInfo( error_code code, const std::string &message ) : code(code),
        message(message) { }
    ErrorInfo( error_code code, const std::string &message, int line, int column ) :
        code(code), message(message), line(line), column(column) { }
    ErrorInfo( const ErrorInfo &that ) { *this = that; }
    ErrorInfo( ErrorInfo &&that )
    {
        message.swap(that.message);
        std::swap(code, that.code);
        std::swap(line, that.line);
        std::swap(column, that.column);
    }
    virtual const char *what() const noexcept override { return message.c_str(); }
    bool operator ==( error_code value ) const { return code == value; }
    ErrorInfo &operator=( const ErrorInfo &that )
    {
        message = that.message;
        code =  that.code;
        line =  that.line;
        column =  that.column;
        return *this;
    }
};

namespace internal {

enum class token_id
{
    NONE, EOS, OBJS, OBJE, COLON, COMMA, STRING, ARRS,
    ARRE, NIL, TRUE, FALSE, NUMBER,
};

struct token
{
    token_id id;
    std::string value;
    int line, column;

    token() : id(token_id::NONE), line(0), column(0) {}
    token( const token &that ) { *this = that; }
    token( token &&that ) { swap(that); }
    token( token_id id, const std::string &value = "", int line = 0, int col = 0 ) : id(id), value(value),
        line(line), column(col) {}
    token &operator=( const token &that )
    {
        id = that.id;
        value = that.value;
        line = that.line;
        column = that.column;
        return *this;
    }
    void swap( token &that )
    {
        std::swap(id, that.id);
        value.swap(that.value);
        std::swap(line, that.line);
        std::swap(column, that.column);
    }
};

class ostream
{
    public:
        ostream() = default;
        virtual ~ostream() = default;
        virtual ostream &operator<<( const std::string &value ) = 0;
        virtual ostream &operator<<( const char *value ) = 0;
        virtual ostream &operator<<( char *value ) = 0;
        virtual ostream &operator<<( char value ) = 0;
        template<class T, typename std::enable_if<std::is_arithmetic<T>::value, int>::type = 0>
        ostream &operator<<( T value )
        {
            this->operator<<( std::to_string(value) );
            return *this;
        }
};

template<typename I>
class iterator_ostream : public ostream
{
    public:
        iterator_ostream( I& first ) : beg_(first)
        {
        }
        ostream & operator<<( char value ) override
        {
            *++beg_ = value;
            return *this;
        }
        ostream & operator<<( const std::string &value ) override
        {
            for (auto it = value.begin(); it != value.end(); ++it)
                *++beg_ = *it;
            return *this;
        }
        ostream & operator<<( const char *value ) override
        {
            while (*value != 0) *++beg_ = *value++;
            return *this;
        }
        ostream & operator<<( char *value ) override { return *this << (const char*) value; }

    protected:
        I beg_;
};

class istream
{
    public:
        istream() = default;
        virtual ~istream() = default;
        virtual int peek() = 0;
        virtual void next() = 0;
        virtual bool eof() const = 0;
        virtual int line() const = 0;
        virtual int column() const = 0;
};

template<typename I>
class iterator_istream : public istream
{
    public:
        iterator_istream( const I& first, const I& last ) : beg_(first), end_(last), line_(1),
            column_(1)
        {
            skip();
        }
        int peek() override
        {
            if (beg_ == end_) return 0;
            return *beg_;
        }
        void next() override
        {
            if (beg_ == end_) return;
            ++beg_;
            ++column_;
            skip();
        }
        bool eof() const override { return beg_ == end_; }
        int line() const override { return line_; }
        int column() const override { return column_; }
    protected:
        I beg_, end_;
        int line_, column_;
        void skip()
        {
            while (!(beg_ == end_) && *beg_ == '\n')
            {
                ++line_;
                column_ = 1;
                ++beg_;
            }
        }
};

class tokenizer
{
    public:
        tokenizer( istream &input ) : input_(input)
        {
            next();
        }

        int line() const { return input_.line(); }
        int column() const { return input_.column(); }

        token &next()
        {
            #define RETURN_TOKEN(x) do { current_ = token(x, "", line, column); input_.next(); return current_; } while (false)
            current_.id = token_id::NONE;
            current_.value.clear();
            while (!input_.eof())
            {
                int c = input_.peek();
                int line = input_.line();
                int column = input_.column();
                switch (c)
                {
                    case ' ':
                    case '\t':
                    case '\r':
                    case '\n':
                        input_.next();
                        break;
                    case '{':
                        RETURN_TOKEN(token_id::OBJS);
                    case '}':
                        RETURN_TOKEN(token_id::OBJE);
                    case '[':
                        RETURN_TOKEN(token_id::ARRS);
                    case ']':
                        RETURN_TOKEN(token_id::ARRE);
                    case ':':
                        RETURN_TOKEN(token_id::COLON);
                    case ',':
                        RETURN_TOKEN(token_id::COMMA);
                    case '"':
                        return current_ = parse_string();
                    case '-':
                    case '0':
                    case '1':
                    case '2':
                    case '3':
                    case '4':
                    case '5':
                    case '6':
                    case '7':
                    case '8':
                    case '9':
                        return current_ = parse_number();
                    default:
                        std::string value = parse_identifier();
                        if (value == "true") return current_ = token(token_id::TRUE, "", line, column);
                        if (value == "false") return current_ = token(token_id::FALSE, "", line, column);
                        if (value == "null") return current_ = token(token_id::NIL, "", line, column);
                        return current_ = token(token_id::NONE, "", line, column);
                }
            }
            return current_ = token(token_id::EOS, "", input_.line(), input_.column());
            #undef RETURN_TOKEN
        }
        token &peek() { return current_; }
        bool expect( token_id type )
        {
            if (current_.id == type)
            {
                next();
                return true;
            }
            return false;
        }
        int error( error_code code, const std::string &msg )
        {
            if (error_.code != error_code::PGERR_OK) return PGR_ERROR;
            error_.code = code;
            error_.message = msg;
            error_.line = current_.line;//input_.line();
            error_.column = current_.column;//input_.column();
            return PGR_ERROR;
        }
        const ErrorInfo &error() const { return error_; }
        int ignore( ) { return ignore_value(); }

    protected:
        token current_;
        istream &input_;
        ErrorInfo error_;

        std::string parse_identifier()
        {
            std::string value;
            while (!input_.eof())
            {
                int c = input_.peek();
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
                {
                    value += (char) c;
                    input_.next();
                }
                else
                    break;
            }
            return value;
        }

        token parse_string()
        {
            std::string value;
            int line = input_.line();
            int column = input_.column();
            if (input_.peek() != '"') goto ERROR;
            while (!input_.eof())
            {
                input_.next();
                int c = input_.peek();
                if (c == '"')
                {
                    input_.next();
                    return token(token_id::STRING, value);
                }
                if (c == '\\')
                {
                    input_.next();
                    c = input_.peek();
                    switch (c)
                    {
                        case '"':  c = '"'; break;
                        case '\\': c = '\\'; break;
                        case '/':  c = '/'; break;
                        case 'b':  c = '\b'; break;
                        case 'f':  c = '\f'; break;
                        case 'r':  c = '\r'; break;
                        case 'n':  c = '\n'; break;
                        case 't':  c = '\t'; break;
                        default: goto ERROR;
                    }
                }
                if (c == 0) goto ERROR;
                value += (char) c;
            }
            ERROR:
            return token(token_id::NONE, "", line, column);
        }

        bool parse_keyword( const std::string &keyword )
        {
            for (auto c : keyword)
            {
                if (input_.peek() != c) return false;
                input_.next();
            }
            return true;
        }

        token parse_number()
        {
            std::string value;
            int line = input_.line();
            int column = input_.column();
            while (!input_.eof())
            {
                int c = input_.peek();
                if (c == '.' || (c >= '0' && c <= '9') || c == 'e' || c == 'E' || c == '+' || c == '-')
                {
                    value += (char) c;
                    input_.next();
                }
                else
                    break;
            }
            return token(token_id::NUMBER, value, line, column);
        }

        int ignore_array()
        {
            if (!expect(token_id::ARRS))
                return error(error_code::PGERR_IGNORE_FAILED, "Invalid array");

            while (peek().id != token_id::ARRE)
            {
                int result = ignore_value();
                if (result != PGERR_OK) return result;
                if (!expect(token_id::COMMA)) break;
            }
            if (!expect(token_id::ARRE))
                return error(error_code::PGERR_IGNORE_FAILED, "Invalid array");
            return PGR_OK;
        }

        int ignore_object()
        {
            if (!expect(token_id::OBJS))
                return error(error_code::PGERR_IGNORE_FAILED, "Invalid object");

            while (peek().id != token_id::OBJE)
            {
                if (!expect(token_id::STRING))
                    return error(error_code::PGERR_IGNORE_FAILED, "Expected field name");
                if (!expect(token_id::COLON))
                    return error(error_code::PGERR_IGNORE_FAILED, "Expected colon");
                int result = ignore_value();
                if (result != PGERR_OK) return result;
                if (!expect(token_id::COMMA)) break;
            }
            if (!expect(token_id::OBJE))
                return error(error_code::PGERR_IGNORE_FAILED, "Invalid object");
            return PGR_OK;
        }

        int ignore_value()
        {
            switch (peek().id)
            {
                case token_id::NONE:
                case token_id::EOS:
                    return error(error_code::PGERR_IGNORE_FAILED, "End of stream");
                case token_id::OBJS:
                    return ignore_object();
                case token_id::ARRS:
                    return ignore_array();
                case token_id::STRING:
                case token_id::NUMBER:
                case token_id::NIL:
                case token_id::TRUE:
                case token_id::FALSE:
                {
                    auto tt = next();
                    if (tt.id == token_id::NONE || tt.id == token_id::EOS)
                        return error(PGERR_IGNORE_FAILED, "End of stream");
                    return PGERR_OK;
                }
                default:
                    return error(error_code::PGERR_IGNORE_FAILED, "Invalid json");
            }
        }
};

template<class T>
class mem_iterator
{
    static_assert(std::is_arithmetic<T>::value, "Invalid template parameters");
    public:
        mem_iterator( const T *begin, size_t count ) : cursor(begin), end(begin + count), empty(0)
        {
        }
        mem_iterator &operator++()
        {
            if (cursor < end) cursor++;
            return *this;
        }
        const T &operator*() const
        {
            if (cursor >= end) return empty;
            return *cursor;
        }
        bool operator==( const mem_iterator<T> &that ) const
        {
            return cursor == that.cursor;
        }
    protected:
        const T *cursor;
        const T *end;
        T empty;
};

} // namespace internal

using namespace protogen_2_0_0::internal;

template<typename T, typename _ = void>
struct is_container : std::false_type {};

template<typename... Ts>
struct is_container_helper {};

template<typename T>
struct is_container<
        T,
        typename std::conditional<
            false,
            is_container_helper<
                typename T::value_type,
                typename T::size_type,
                typename T::allocator_type,
                typename T::iterator,
                typename T::const_iterator,
                decltype(std::declval<T>().size()),
                decltype(std::declval<T>().begin()),
                decltype(std::declval<T>().end()),
                decltype(std::declval<T>().clear()),
                decltype(std::declval<T>().empty())
                >,
            void
            >::type
        > : public std::true_type {};

template<typename T, typename E = void> struct json;

struct json_context
{
    tokenizer *tok;
    ostream *os;
    bool required;
    uint32_t mask;
    json_context() : tok(nullptr), os(nullptr), required(false), mask(0) {}
};

template<typename T> class field
{
    static_assert(std::is_arithmetic<T>::value, "Invalid arithmetic type");
    protected:
        T value_;
        bool empty_;
    public:
        typedef T value_type;
        field() { clear(); }
        field( const field<T> &that ) { this->empty_ = that.empty_; if (!empty_) this->value_ = that.value_; }
        field( field<T> &&that ) { this->empty_ = that.empty_; if (!empty_) json<T>::swap(this->value_, that.value_); }
        void swap( field<T> &that ) { std::swap(this->value_, that.value_); std::swap(this->empty_, that.empty_); }
        void swap( T &that ) { std::swap(this->value_, that); empty_ = false; }
        const T operator()() const { return value_; }
        void operator()(const T &value ) { this->value_ = value; this->empty_ = false; }
        bool empty() const { return empty_; }
        void clear() { value_ = (T) 0; empty_ = true; }
        field<T> &operator=( const field<T> &that ) { this->empty_ = that.empty_; if (!empty_) this->value_ = that.value_; return *this; }
        field<T> &operator=( const T &that ) { this->empty_ = false; this->value_ = that; return *this; }
        bool operator==( const T &that ) const { return !this->empty_ && this->value_ == that; }
        bool operator!=( const T &that ) const { return !this->empty_ && this->value_ != that; }
        bool operator==( const field<T> &that ) const { return this->empty_ == that.empty_ && this->value_ == that.value_;  }
        bool operator!=( const field<T> &that ) const { return this->empty_ != that.empty_ || this->value_ != that.value_;  }
        operator T() const { return this->value_; }
};

template<typename T>
struct json<field<T>, typename std::enable_if<std::is_arithmetic<T>::value>::type>
{
    static int read( json_context &ctx, field<T> &value )
    {
        T temp;
        json<T>::clear(temp);
        int result = json<T>::read(ctx, temp);
        value = temp;
        return result;
    }
    static void write( json_context &ctx, const field<T> &value )
    {
        T temp = value();
        json<T>::write(ctx, temp);
    }
    static bool empty( const field<T> &value ) { return value.empty(); }
    static void clear( field<T> &value ) { value.clear(); }
    static bool equal( const field<T> &a, const field<T> &b ) { return a == b; }
    static void swap( field<T> &a, field<T> &b ) { std::swap(a, b); }
};

template<typename T, typename std::enable_if<std::is_floating_point<T>::value, int>::type = 0>
static T string_to_number( const std::string &text )
{
    double value;
#if defined(_WIN32) || defined(_WIN64)
    static _locale_t loc = _create_locale(LC_NUMERIC, "C");
    if (loc == nullptr) return 0;
    value = _strtod_l(text.c_str(), nullptr, loc);
#else
    static locale_t loc = newlocale(LC_NUMERIC_MASK, "C", 0);
    if (loc == 0) return 0;
#ifdef __USE_GNU
    value = strtod_l(text.c_str(), nullptr, loc);
#else
    locale_t old = uselocale(loc);
    if (old == 0) return 0;
    value = strtod(text.c_str(), nullptr);
    uselocale(old);
#endif
#endif
    return static_cast<T>(value);
}

template<typename T, typename std::enable_if<std::is_integral<T>::value && std::is_signed<T>::value, int>::type = 0>
T string_to_number( const std::string &text )
{
#if defined(_WIN32) || defined(_WIN64)
    return static_cast<T>( _strtoi64(text.c_str(), nullptr, 10) );
#else
    return static_cast<T>( strtol(text.c_str(), nullptr, 10) );
#endif
}

template<typename T, typename std::enable_if<std::is_integral<T>::value && !std::is_signed<T>::value, int>::type = 0>
T string_to_number( const std::string &text )
{
#if defined(_WIN32) || defined(_WIN64)
    return static_cast<T>( _strtoui64(text.c_str(), nullptr, 10) );
#else
    return static_cast<T>( strtoul(text.c_str(), nullptr, 10) );
#endif
}

template<typename T>
struct json<T, typename std::enable_if<std::is_arithmetic<T>::value>::type>
{
    static int read( json_context &ctx, T &value )
    {
        auto &tt = ctx.tok->peek();
        if (tt.id == token_id::NIL) return PGR_NIL;
        if (tt.id != token_id::NUMBER)
            return ctx.tok->error(error_code::PGERR_INVALID_VALUE, "Invalid numeric value");
        value = string_to_number<T>(tt.value);
        ctx.tok->next();
        return PGR_OK;
    }
    static void write( json_context &ctx, const T &value ) { (*ctx.os) << value; }
    static bool empty( const T &value ) { (void) value; return false; }
    static void clear( T &value ) { value = (T) 0; }
    static bool equal( const T &a, const T &b ) { return a == b; }
    static void swap( T &a, T &b ) { std::swap(a, b); }
};

template<typename T>
struct json<T, typename std::enable_if<is_container<T>::value>::type >
{
    static int read( json_context &ctx, T &value )
    {
        if (ctx.tok->peek().id == token_id::NIL) return PGR_NIL;
        if (!ctx.tok->expect(token_id::ARRS))
            return ctx.tok->error(error_code::PGERR_INVALID_OBJECT, "Invalid object");
        while (true)
        {
            typename T::value_type temp;
            int result = json<typename T::value_type>::read(ctx, temp);
            if (result == PGR_ERROR) return result;
            if (result == PGR_OK) value.push_back(temp);
            if (!ctx.tok->expect(token_id::COMMA)) break;
        }
        if (!ctx.tok->expect(token_id::ARRE))
            return ctx.tok->error(error_code::PGERR_INVALID_OBJECT, "Invalid object");
        return PGR_OK;
    }
    static void write( json_context &ctx, const T &value )
    {
        (*ctx.os) <<  '[';
        size_t i = 0, t = value.size();
        for (auto it = value.begin(); it != value.end(); ++it, ++i)
        {
            json<typename T::value_type>::write(ctx, *it);
            if (i + 1 < t) (*ctx.os) <<  ',';
        }
        (*ctx.os) <<  ']';
    }
    static bool empty( const T &value ) { return value.empty(); }
    static void clear( T &value ) { value.clear(); }
    static bool equal( const T &a, const T &b ) { return a == b; }
    static void swap( T &a, T &b ) { std::swap(a, b); }
};


// Base64 encoder/decoder based on Joe DF's implementation
// Original source at <https://github.com/joedf/base64.c> (MIT licensed)
template <>
struct json< std::vector<uint8_t> >
{
    static int b64_int( int ch )
    {
        if (ch == '+') return 62;
        if (ch == '/') return 63;
        if (ch == '=') return 64;
        if (ch >= '0' && ch <= '9') return ch + 4;
        if (ch >= 'A' && ch <= 'Z') return ch - 'A';
        if (ch >= 'a' && ch <= 'z') return (ch - 'a') + 26;
        return 0;
    }
    static void write( json_context &ctx, const std::vector<uint8_t> &value )
    {
        static const char *B64_SYMBOLS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        char o[5] = { 0 };
        size_t i = 0;
        size_t size = value.size();

        (*ctx.os) <<  '"';

        for (i = 0; i + 2 < size; i += 3)
        {
            o[0] = B64_SYMBOLS[ (value[i] & 0xFF) >> 2 ];
            o[1] = B64_SYMBOLS[ ((value[i] & 0x03) << 4) | ((value[i + 1] & 0xF0) >> 4) ];
            o[2] = B64_SYMBOLS[ ((value[i+1] & 0x0F) << 2) | ((value[i+2] & 0xC0) >> 6) ];
            o[3] = B64_SYMBOLS[ value[i+2] & 0x3F ];
            (*ctx.os) <<  o;
        }

        if (size - i)
        {
            o[0] = B64_SYMBOLS[ (value[i] & 0xFF) >> 2 ];
            o[1] = B64_SYMBOLS[ ((value[i] & 0x03) << 4) ];
            o[2] = '=';
            o[3] = '=';

            if (size - i == 2)
            {
                o[1] = B64_SYMBOLS[ ((value[i] & 0x03) << 4) | ((value[i + 1] & 0xF0) >> 4) ];
                o[2] = B64_SYMBOLS[ ((value[i+1] & 0x0F) << 2) ];
            }

            (*ctx.os) <<  o;
        }
        (*ctx.os) <<  '"';
    }
    static int read( json_context &ctx, std::vector<uint8_t> &value )
    {
        if (ctx.tok->peek().id == token_id::NIL) return PGR_NIL;
        if (ctx.tok->peek().id != token_id::STRING)
            return ctx.tok->error(error_code::PGERR_INVALID_OBJECT, "Invalid string");

        size_t k = 0;
        int s[4];
        std::string text = ctx.tok->peek().value;
        ctx.tok->next();
        const char *ptr = text.c_str();

        while (true)
        {
            // read 4 characters
            for (size_t j = 0; j < 4; ++j)
            {
                int ch = *ptr++;
                if (ch == 0)
                {
                    if (j != 0) ctx.tok->error(error_code::PGERR_INVALID_OBJECT, "Invalid base64 data");
                    return PGR_OK;
                }
                s[j] = b64_int(ch);
            }
            // decode base64 tuple
            value.push_back( (uint8_t) (((s[0] & 0xFF) << 2 ) | ((s[1] & 0x30) >> 4)) );
            if (s[2] != 64)
            {
                value.push_back( (uint8_t) (((s[1] & 0x0F) << 4) | ((s[2] & 0x3C) >> 2)) );
                if ((s[3]!=64))
                {
                    value.push_back( (uint8_t) (((s[2] & 0x03) << 6) | s[3]) );
                    k+=3;
                }
                else
                    k+=2;
            }
            else
                k+=1;
        }
    }
    static bool empty( const std::vector<uint8_t> &value ) { return value.empty(); }
    static void clear( std::vector<uint8_t> &value ) { value.clear(); }
    static bool equal( const std::vector<uint8_t> &a, const std::vector<uint8_t> &b ) { return a == b; }
    static void swap( std::vector<uint8_t> &a, std::vector<uint8_t> &b ) { std::swap(a, b); }
};

template<>
struct json<bool, void>
{
    static int read( json_context &ctx, bool &value )
    {
        auto &tt = ctx.tok->peek();
        if (tt.id == token_id::NIL) return PGR_NIL;
        if (tt.id != token_id::TRUE && tt.id != token_id::FALSE)
            return ctx.tok->error(error_code::PGERR_INVALID_VALUE, "Invalid boolean value");
        value = tt.id == token_id::TRUE;
        ctx.tok->next();
        return PGR_OK;
    }
    static void write( json_context &ctx, const bool &value )
    {
        (*ctx.os) <<  (value ? "true" : "false");
    }
    static bool empty( const bool &value ) { (void) value; return false; }
    static void clear( bool &value ) { value = false; }
    static bool equal( const bool &a, const bool &b ) { return a == b; }
    static void swap( bool &a, bool &b ) { std::swap(a, b); }
};

template<>
struct json<std::string, void>
{
    static int read( json_context &ctx, std::string &value )
    {
        auto tt = ctx.tok->peek();
        if (tt.id == token_id::NIL) return PGR_NIL;
        if (!ctx.tok->expect(token_id::STRING))
            return ctx.tok->error(error_code::PGERR_INVALID_VALUE, "Invalid string value");
        value = tt.value;
        return PGR_OK;
    }
    static void write( json_context &ctx, const std::string &value )
    {
        (*ctx.os) <<  '"';
        for (std::string::const_iterator it = value.begin(); it != value.end(); ++it)
        {
            switch (*it)
            {
                case '"':  (*ctx.os) <<  "\\\""; break;
                case '\\': (*ctx.os) <<  "\\\\"; break;
                case '/':  (*ctx.os) <<  "\\/"; break;
                case '\b': (*ctx.os) <<  "\\b"; break;
                case '\f': (*ctx.os) <<  "\\f"; break;
                case '\r': (*ctx.os) <<  "\\r"; break;
                case '\n': (*ctx.os) <<  "\\n"; break;
                case '\t': (*ctx.os) <<  "\\t"; break;
                default:   (*ctx.os) <<  *it;
            }
        }
        (*ctx.os) <<  '"';
    }
    static bool empty( const std::string &value ) { return value.empty(); }
    static void clear( std::string &value ) { value.clear(); }
    static bool equal( const std::string &a, const std::string &b ) { return a == b; }
    static void swap( std::string &a, std::string &b ) { a.swap(b); }
};

template <typename T>
#if !defined(_WIN32)
constexpr
#endif
T rol( T value, size_t count )
{
	static_assert(std::is_unsigned<T>::value, "Unsupported signed type");
	return (T) ((value << count) | (value >> (-count & (sizeof(T) * 8 - 1))));
}

template<typename T>
static inline std::string reveal( const T *value, size_t length )
{
    uint8_t mask = rol<uint8_t>(0x93U, length % 8);
	std::string result(length, ' ');
	for (size_t i = 0; i < length; ++i)
		result[i] = (char) ((uint8_t) value[i] ^ mask);
	return result;
}

template<typename T, typename J = json<T> >
static int read_object( json_context &ctx, T &object )
{
    if (ctx.tok->peek().id == token_id::NIL) return PGR_NIL;
    if (!ctx.tok->expect(token_id::OBJS))
        return ctx.tok->error(error_code::PGERR_INVALID_OBJECT, "objects must start with '{'");
    if (!ctx.tok->expect(token_id::OBJE))
    {
        while (true)
        {
            std::string name = ctx.tok->peek().value;
            if (!ctx.tok->expect(token_id::STRING))
                return ctx.tok->error(error_code::PGERR_INVALID_NAME, "object key must be string");
            if (!ctx.tok->expect(token_id::COLON))
                return ctx.tok->error(error_code::PGERR_INVALID_SEPARATOR, "field name and value must be separated by ':'");
            int result = J::read_field(ctx, name, object);
            if (result == PGR_ERROR) return result;
            if (result != PGR_OK)
            {
                result = ctx.tok->ignore();
                if (result == PGR_ERROR) return result;
            }
            if (ctx.tok->expect(token_id::COMMA)) continue;
            if (ctx.tok->expect(token_id::OBJE)) break;
            return ctx.tok->error(error_code::PGERR_INVALID_OBJECT, "invalid JSON object");
        };
    }
    if (ctx.required && J::is_missing(ctx))
        return error_code::PGERR_MISSING_FIELD;
    return PGR_OK;
}

/*
 * Copyright (C) 2012 William Swanson
 *               2018 Niklas Gürtler
 *
 * <https://github.com/Erlkoenig90/map-macro>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the names of the authors or
 * their institutions shall not be used in advertising or otherwise to
 * promote the sale, use or other dealings in this Software without
 * prior written authorization from the authors.
 */

#ifndef PG_MAP_H_INCLUDED
#define PG_MAP_H_INCLUDED

#define PG_EVAL0(...) __VA_ARGS__
#define PG_EVAL1(...) PG_EVAL0(PG_EVAL0(PG_EVAL0(__VA_ARGS__)))
#define PG_EVAL2(...) PG_EVAL1(PG_EVAL1(PG_EVAL1(__VA_ARGS__)))
#define PG_EVAL3(...) PG_EVAL2(PG_EVAL2(PG_EVAL2(__VA_ARGS__)))
#define PG_EVAL4(...) PG_EVAL3(PG_EVAL3(PG_EVAL3(__VA_ARGS__)))
#define PG_EVAL5(...) PG_EVAL4(PG_EVAL4(PG_EVAL4(__VA_ARGS__)))

#ifdef _MSC_VER
// MSVC needs more evaluations
#define PG_EVAL6(...) PG_EVAL5(PG_EVAL5(PG_EVAL5(__VA_ARGS__)))
#define PG_EVAL(...)  PG_EVAL6(PG_EVAL6(__VA_ARGS__))
#else
#define PG_EVAL(...)  PG_EVAL5(__VA_ARGS__)
#endif

#define PG_MAP_END(...)
#define PG_MAP_OUT

#define PG_EMPTY()
#define PG_DEFER(id) id PG_EMPTY()

#define PG_MAP_GET_END2() 0, PG_MAP_END
#define PG_MAP_GET_END1(...) PG_MAP_GET_END2
#define PG_MAP_GET_END(...) PG_MAP_GET_END1
#define PG_MAP_NEXT0(test, next, ...) next PG_MAP_OUT
#define PG_MAP_NEXT1(test, next) PG_DEFER ( PG_MAP_NEXT0 ) ( test, next, 0)
#define PG_MAP_NEXT(test, next)  PG_MAP_NEXT1(PG_MAP_GET_END test, next)
#define PG_MAP_INC(X) (X+1)

#define PG_MAP0_UD_I(f, userdata, index, x, peek, ...) f(x,userdata,index) PG_DEFER ( PG_MAP_NEXT(peek, PG_MAP1_UD_I) ) ( f, userdata, PG_MAP_INC(index), peek, __VA_ARGS__ )
#define PG_MAP1_UD_I(f, userdata, index, x, peek, ...) f(x,userdata,index) PG_DEFER ( PG_MAP_NEXT(peek, PG_MAP0_UD_I) ) ( f, userdata, PG_MAP_INC(index), peek, __VA_ARGS__ )

/**
 * Applies the function macro `f` to each of the remaining parameters, passes userdata as the second parameter to each invocation,
 * and the index of the invocation as the third parameter,
 * e.g. MAP_UD_I(f, x, a, b, c) evaluates to f(a, x, 0) f(b, x, 1) f(c, x, 2)
 */
#define PG_MAP_UD_I(f, userdata, ...) PG_EVAL(PG_MAP1_UD_I(f, userdata, 0, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

#endif // PG_MAP_H_INCLUDED

#define PG_DIF_EX(field_id, field_name, field_label) \
    if (name == field_label) { \
        int result = protogen_2_0_0::json<decltype(value.field_name)>::read(ctx, value.field_name); \
        if (result == PGR_OK) ctx.mask |= (1 << field_id); \
        return result; \
    } else

#define PG_DIF(field_name,user_data,field_id) \
    PG_DIF_EX(field_id, field_name, PG_MKSTR(field_name) )

#define PG_SIF_EX(field_name, field_label) \
    if (!protogen_2_0_0::json<decltype(value.field_name)>::empty(value.field_name)) \
    { \
        if (!first) (*ctx.os) <<  ','; \
        first = false; \
        (*ctx.os) <<  '\"' << field_label << "\":"; \
        protogen_2_0_0::json<decltype(value.field_name)>::write(ctx, value.field_name); \
    }

#define PG_SIF(field_name,user_data,field_id) \
    PG_SIF_EX(field_name, PG_MKSTR(field_name) )

#define PG_EIF(field_name,user_data,field_id) \
    if (!protogen_2_0_0::json<decltype(value.field_name)>::empty(value.field_name)) return false;

#define PG_CLL(field_name,user_data,field_id) \
    protogen_2_0_0::json<decltype(value.field_name)>::clear(value.field_name);

#define PG_QIF(field_name,user_data,field_id) \
    if (!protogen_2_0_0::json<decltype(a.field_name)>::equal(a.field_name, b.field_name)) return false;

#define PG_SLL(field_name,user_data,field_id) \
    protogen_2_0_0::json<decltype(a.field_name)>::swap(a.field_name, b.field_name);

#define PG_MIF(field_name,user_data,field_id) \
    if (!(ctx.mask & (1 << field_id))) { name = PG_MKSTR(field_name); } else

#define PG_JSON(type, ...) \
    namespace protogen_2_0_0 { \
    template<> \
    struct json<type> \
    { \
        static int read( json_context &ctx, type &value ) \
        { \
            return read_object(ctx, value); \
        } \
        static int read_field( json_context &ctx, const std::string &name, type &value ) \
        { \
            PG_EVAL(PG_MAP_UD_I(PG_DIF, 0, __VA_ARGS__)) \
            return PGR_ERROR; \
        } \
        static void write( json_context &ctx, const type &value ) \
        { \
            bool first = true; \
            (*ctx.os) <<  '{'; \
            PG_MAP_UD_I(PG_SIF, 0, __VA_ARGS__) \
            (*ctx.os) <<  '}'; \
        } \
        static bool empty( const type &value ) \
        { \
            PG_MAP_UD_I(PG_EIF, 0, __VA_ARGS__) \
            return true; \
        } \
        static void clear( type &value ) \
        { \
            PG_MAP_UD_I(PG_CLL, 0, __VA_ARGS__) \
        } \
        static bool equal( const type &a, const type &b ) \
        { \
            PG_MAP_UD_I(PG_QIF, 0, __VA_ARGS__) \
        } \
        static void swap( type &a, type &b ) \
        { \
            PG_MAP_UD_I(PG_SLL, 0, __VA_ARGS__) \
        } \
        static bool is_missing( json_context &ctx ) \
        { \
            std::string name; \
            PG_MAP_UD_I(PG_MIF, 0, __VA_ARGS__) \
            return false; \
            ctx.tok->error(PGERR_MISSING_FIELD, std::string("Missing field '") + name + "'"); \
            return true; \
        } \
    };}

template<typename T>
bool deserialize( T &value, protogen_2_0_0::tokenizer& tok, bool required = false, ErrorInfo *err = nullptr )
{
    json_context ctx;
    ctx.tok = &tok;
    ctx.required = required;
    if (json<T>::read(ctx, value) != PGR_ERROR) return true;
    if (err != nullptr) *err = tok.error();
    return false;
}

template<typename T>
bool deserialize( T &value, istream &in, bool required = false, ErrorInfo *err = nullptr )
{
    tokenizer tok(in);
    return deserialize<T>(value, tok, required, err);
}

template<typename T>
bool deserialize( T &value, const std::string &in, bool required = false, ErrorInfo *err = nullptr )
{
    iterator_istream<std::string::const_iterator> is(in.begin(), in.end());
    return deserialize<T>(value, is, required, err);
}

template<typename T>
bool deserialize( T &value, const std::vector<char> &in, bool required = false, ErrorInfo *err = nullptr )
{
    iterator_istream<std::vector<char>::const_iterator> is(in.begin(), in.end());
    return deserialize<T>(value, is, required, err);
}

template<typename T>
bool deserialize( T &value, std::istream &in, bool required = false, ErrorInfo *err = nullptr )
{
    bool skip = in.flags() & std::ios_base::skipws;
    std::noskipws(in);
    std::istream_iterator<char> end;
    std::istream_iterator<char> begin(in);
    iterator_istream<std::istream_iterator<char>> is(begin, end);
    bool result = deserialize<T>(value, is, required, err);
    if (skip) std::skipws(in);
    return result;
}

template<typename T>
bool deserialize( T &value, const char *in, size_t len, bool required = false, ErrorInfo *err = nullptr )
{
    auto begin = mem_iterator<char>(in, len);
    auto end = mem_iterator<char>(in + len, 0);
    iterator_istream<mem_iterator<char>> is(begin, end);
    return deserialize<T>(value, is, required, err);
}

template<typename T>
void serialize( const T &value, ostream &out )
{
    json_context ctx;
    ctx.os = &out;
    json<T>::write(ctx, value);
}

template<typename T>
void serialize( const T &value, std::string &out )
{
    typedef std::back_insert_iterator<std::string> ittype;
    ittype begin(out);
    iterator_ostream<ittype> os(begin);
    serialize<T>(value, os);
}

template<typename T>
void serialize( const T &value, std::vector<char> &out )
{
    typedef std::back_insert_iterator<std::vector<char>> ittype;
    ittype begin(out);
    iterator_ostream<ittype> os(begin);
    serialize<T>(value, os);
}

template<typename T>
void serialize( const T &value, std::ostream &out )
{
    typedef std::ostream_iterator<char> ittype;
    ittype begin(out);
    iterator_ostream<ittype> os(begin);
    serialize<T>(value, os);
}

template<typename T, typename J = protogen_2_0_0::json<T>>
void clear( T &value ) { json<T>::clear(value); }

template<typename T, typename J = protogen_2_0_0::json<T>>
bool empty( const T &value ) { return json<T>::empty(value); }

// parent class for messages
template<typename T, typename J>
struct message
{
    typedef T underlying_type;
    typedef J serializer_type;
    virtual ~message() = default;
    virtual bool deserialize( tokenizer& tok, bool required = false, ErrorInfo *err = nullptr ) = 0;
    virtual bool deserialize( istream &in, bool required = false, ErrorInfo *err = nullptr )
    {
        tokenizer tok(in);
        return deserialize(tok, required, err);
    }
    virtual bool deserialize( const std::string &in, bool required = false, ErrorInfo *err = nullptr )
    {
        iterator_istream<std::string::const_iterator> is(in.begin(), in.end());
        return deserialize(is, required, err);
    }
    virtual bool deserialize( const std::vector<char> &in, bool required = false, ErrorInfo *err = nullptr )
    {
        iterator_istream<std::vector<char>::const_iterator> is(in.begin(), in.end());
        return deserialize(is, required, err);
    }
    virtual bool deserialize( std::istream &in, bool required = false, ErrorInfo *err = nullptr )
    {
        bool skip = in.flags() & std::ios_base::skipws;
        std::noskipws(in);
        std::istream_iterator<char> end;
        std::istream_iterator<char> begin(in);
        iterator_istream<std::istream_iterator<char>> is(begin, end);
        bool result = deserialize(is, required, err);
        if (skip) std::skipws(in);
        return result;
    }
    virtual bool deserialize( const char *in, size_t len, bool required = false, ErrorInfo *err = nullptr )
    {
        auto begin = mem_iterator<char>(in, len);
        auto end = mem_iterator<char>(in + len, 0);
        iterator_istream<mem_iterator<char>> is(begin, end);
        return deserialize(is, required, err);
    }
    virtual void serialize( ostream &out ) const = 0;
    virtual void serialize( std::string &out ) const
    {
        typedef std::back_insert_iterator<std::string> ittype;
        ittype begin(out);
        iterator_ostream<ittype> os(begin);
        serialize(os);
    }
    virtual void serialize( std::vector<char> &out ) const
    {
        typedef std::back_insert_iterator<std::vector<char>> ittype;
        ittype begin(out);
        iterator_ostream<ittype> os(begin);
        serialize(os);
    }
    virtual void serialize( std::ostream &out ) const
    {
        typedef std::ostream_iterator<char> ittype;
        ittype begin(out);
        iterator_ostream<ittype> os(begin);
        serialize(os);
    }
    virtual void clear() = 0;
    virtual bool empty() const  = 0;
    virtual bool equal( const T &that ) const = 0;
    bool operator==( const T &that ) const { return equal(that); }
    bool operator!=( const T &that ) const { return !equal(that); }
};

#define PG_ENTITY(N,O,S) \
    struct N : public O, public protogen_2_0_0::message< O, S > \
    { \
        typedef O value_type; \
        typedef S serializer_type; \
        typedef protogen_2_0_0::ErrorInfo ErrorInfo; \
        N() = default; \
        N( const N& ) = default; \
        N( N &&that ) { S::swap(*this, that); } \
        N &operator=( const N & ) = default; \
        using protogen_2_0_0::message<O, S>::serialize; \
        using protogen_2_0_0::message<O, S>::deserialize; \
        bool deserialize( protogen_2_0_0::tokenizer& tok, bool required = false, \
            protogen_2_0_0::ErrorInfo *err = nullptr ) override \
        { \
            protogen_2_0_0::json_context ctx; \
            ctx.tok = &tok; \
            ctx.required = required; \
            int result = S::read(ctx, *this); \
            if (result == protogen_2_0_0::PGR_OK) return true; \
            if (err != nullptr) *err = tok.error(); \
            return false; \
        } \
        void serialize( protogen_2_0_0::ostream &out ) const override \
        { \
            protogen_2_0_0::json_context ctx; \
            ctx.os = &out; \
            S::write(ctx, *this); \
        } \
        void clear() override { S::clear(*this); } \
        bool empty() const override { return S::empty(*this); } \
        bool equal( const O &that ) const override { return S::equal(*this, that); } \
        void swap( O &that ) { S::swap(*this, that); } \
    };

#define PG_ENTITY_SERIALIZER(N,O,S) \
    namespace protogen_2_0_0 { \
    template<> \
    struct json<N> \
    { \
        static int read( json_context &ctx, O &value ) { return S::read(ctx, value); } \
        static int read_field( json_context &ctx, const std::string &name, O &value ) { return S::read_field(ctx, name, value); } \
        static void write( json_context &ctx, const O &value ) { S::write(ctx, value); } \
        static bool empty( const O &value ) { return S::empty(value); } \
        static void clear( O &value ) { S::clear(value); } \
        static bool equal( const O &a, const O &b ) { return S::equal(a, b); } \
        static void swap( O &a, O &b ) { S::swap(a, b); } \
        static bool is_missing( json_context &ctx ) { return S::is_missing(ctx); } \
    };}

} // namespace protogen_2_0_0


#endif // PROTOGEN_2_0_0
