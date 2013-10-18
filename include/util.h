#pragma once

inline size_t append_path(char* dest, size_t dest_len, char const* source, size_t source_len)
{
    memset(dest, '\0', dest_len);
    if (dest_len < source_len + 2)
        return 0;

    strncpy(dest, source, dest_len);
    dest[source_len] = ';';
    return source_len + 1;
}
