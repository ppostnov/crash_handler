#pragma once
#include <stdint.h>
#include "export.h"
#include "types.h"
#include "util.h"

// Handling application crashes.
namespace crash_handler
{

struct CRASH_HANDLER_API handler
{
    handler(primary_handler_f const* ph = nullptr);
    ~handler();

    struct impl;
    impl*  pimpl_;
};

} // namespace crash_handler
