#pragma once


// Handling application crashes.
// Usage: call set_process_handlers as soon as your application is started.
namespace crash_handler
{
struct ch
{
    ch();
};

static ch handler_object;
} // namespace crash_handler
