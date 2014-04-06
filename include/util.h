#pragma once
#include <assert.h>
#include <stdint.h>
#include <string.h>

namespace util
{

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

template <int str_len>
struct fixed_string
{
    fixed_string()
    {
        clear();
    }

    template <int other_str_len>
    fixed_string(fixed_string<other_str_len> const& other)
    {
        assert(other_str_len == str_len);

        memcpy(str_, other.str_, str_len);
        str_[str_len + 1] = 0;
    }

    template <int other_str_len>
    fixed_string& operator= (fixed_string<other_str_len> const& other)
    {
        assert(other_str_len <= str_len);

        memcpy(str_, other.str_, other_str_len);
        len_ = other_str_len;
        memset(eos(), 0, free());
    }

    fixed_string& operator= (char const* src)
    {
        char const* eos_ = src;
        while (*eos_++);
        uint16_t len = (eos_ - src - 1);

        assert(len <= str_len);

        memcpy(str_, src, len);
        len_ = len;
        memset(eos(), 0, free());

        return *this;
    }

    uint16_t append(char const* src, uint16_t len = 0)
    {
        if (0 == len)
        {
            char const* eos_ = src;
            while (*eos_++);
            len = (eos_ - src - 1);
        }

        if (len > free())
            return 0;

        memcpy(eos(), src, len);
        len_ += len;
        return len;
    }

    void clear()
    {
        len_ = 0;
        memset(str_, 0, str_len + 1);
    }

    uint16_t resize(uint16_t size)
    {
        if (size < len_)
        {
            len_ = size;
            memset(str_ + len_ + 1, 0, free());
        }
        return len_;
    }

    char const* c_str() const
    {
        return str_;
    }

    uint16_t size() const
    {
        return len_;
    }

    uint16_t capacity() const
    {
        return str_len;
    }

private:
    uint16_t free() const
    {
        return str_len - len_;
    }

    char* eos() const
    {
        return (char*)(str_ + len_);
    }

    char      str_[str_len + 1];
    uint16_t  len_;
};

#define LOG(something) \
    std::cout << something << std::endl;

} // namespace util

