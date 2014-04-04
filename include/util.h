#pragma once
#include <stdint.h>
#include <string.h>

namespace util
{

//inline size_t append_path(char* dest, size_t dest_len, char const* source, size_t source_len)
//{
//    if (source_len > strlen(source))
//        source_len = strlen(source);
//
//    memset(dest, '\0', dest_len);
//    if (dest_len < source_len + 2)
//        return 0;
//
//    strncpy(dest, source, dest_len);
//    dest[source_len] = ';';
//    return source_len + 1;
//}

struct path_composer
{
    static uint16_t const  PATH_LENGTH = 1024;

    path_composer();

    uint16_t append(char const* src, uint16_t len = 0);

    void clear();

    char const* path() const;

private:
    char  path_[PATH_LENGTH];
    uint16_t  len_;
    char const*  eos_;
};

struct fixed_string
{
    fixed_string(int n);
    fixed_string(fixed_string const& other);
    fixed_string& operator= (fixed_string const& other);

    fixed_string& operator= (char const* str);

    void append(char const* src, uint16_t len = 0);
    void clear();
    void resize(uint16_t size);

    char const* c_str() const;
    uint16_t size() const;

private:
    char*     str_;
    uint16_t  len_;
};

#define LOG(something) \
    std::cout << something << std::endl;

} // namespace util

