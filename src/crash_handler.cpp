#include "crash_handler.h"
#include "crash_handler_impl.h"

namespace crash_handler
{

handler::impl::impl(primary_handler_f const* ph)
{
    ph_ = 0;

    if (ph)
        ph_ = *ph;

    memset(&info      , 0, sizeof(info      ));
    memset(&time_t_buf, 0, sizeof(time_t_buf));
    memset(&tm_buf    , 0, sizeof(tm_buf    ));
    memset(time_buf   , 0, TIME_BUF_SIZE     );

    install_handlers();
}

handler::impl::~impl()
{
    remove_handlers();
}

void handler::impl::report_and_exit()
{
    // crash_info ready here (without pretty names yet)
    if (!ph_ || !ph_(info))
    {
        // print to file
    }

    if (IsDebuggerPresent())
        __debugbreak();

    TerminateProcess(GetCurrentProcess(), 1);
}


handler::handler(primary_handler_f const* ph)
#ifdef _WIN32
    : pimpl_(new win_impl(ph))
#elif __linux__
    : pimpl_(new linux_impl(ph))
#elif
#   error "Unsupported platform"
#endif
{ }

handler::~handler()
{
    delete pimpl_;
}

} // namespace crash_handler
