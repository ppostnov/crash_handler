#include "util.h"

namespace util
{
path_composer::path_composer()
{
    clear();
}


uint16_t path_composer::append(char const* src, uint16_t len)
{
    if (0 == len)
    {
        eos_ = src;
        while (*eos_++);
        len = (eos_ - src - 1);

        if (0 == len)
            return 0;
    }

    if (0 == len_)
    {
        if (PATH_LENGTH < len + 1)
            return 0;

        strncpy(path_, src, PATH_LENGTH);

        len_ += len;
        return len;
    }
    else
    {
        if (PATH_LENGTH - len_ - 1 < len + 1)
            return 0;

        path_[len_] = ';';
        strncpy(path_ + len_ + 1, src, PATH_LENGTH - len_ - 1);
        len_ += len + 1;

        return len + 1;
    }
}

void path_composer::clear()
{
    len_ = 0;
    memset(path_, 0, PATH_LENGTH);
}

char const* path_composer::path() const
{
    return path_;
}

} // namespace util

