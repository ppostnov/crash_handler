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

    dumpfile.append("crash_");

    static uint16_t const buf_size = 1024;
    static char buf[buf_size];
    memset(buf, 0, buf_size);

    GetModuleFileName(NULL, buf, buf_size);
    dumpfile.append(strrchr(buf, '\\') + 1);

    install_handlers();
}

handler::impl::~impl()
{
    remove_handlers();
}

void handler::impl::report_and_exit()
{
    info.pid         = current_process_id();
    info.crashed_tid = current_thread_id();

    get_context();
    get_stack  ();

    // crash_info ready here (without pretty names yet)
    if (!ph_ || !ph_(info))
    {
        dumpfile_append_date();
        // print
    }

    if (IsDebuggerPresent())
        __debugbreak();

    TerminateProcess(GetCurrentProcess(), 1);
}

void handler::impl::dumpfile_append_date()
{
    dumpfile.clear();

    static uint16_t const  buf_size = 20;
    static char buf[buf_size];
    memset(buf, 0, buf_size);

    time_t_buf = time(NULL);
    localtime_s(&tm_buf, &time_t_buf);
    strftime(buf, buf_size, "_%Y-%m-%d_%H%M%S", &tm_buf);

    dumpfile.append(buf);
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
