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
    handler(callbacks const* cbs = nullptr);
    ~handler();

private:
    struct impl;
    impl*  pimpl_;
};

} // namespace crash_handler
