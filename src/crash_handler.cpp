#include "crash_handler.h"


namespace crash_handler
{

struct handler::impl
{
    struct mem_store
    {
        mem_store()
        {
            name_len      = 0;
            suffix_len    = 0;

            memset(&time_t_buf, 0, sizeof(time_t_buf));
            memset(&tm_buf    , 0, sizeof(tm_buf)    );
            memset(stack_buf  , 0, STACK_BUF_SIZE    );
            memset(time_buf   , 0, TIME_BUF_SIZE     );
        }

        ~mem_store()
        { }

        //EXCEPTION_RECORD  exception_record;
        //CONTEXT           exception_context;

        fixed_string<DUMP_FILENAME_SIZE>  dumpfile;

        size_t     name_len;
        size_t     suffix_len;

        time_t     time_t_buf;
        struct tm  tm_buf;

        stack_frame_t     stack_buf[STACK_BUF_SIZE];
        char              time_buf [TIME_BUF_SIZE ];
        std::ofstream     ofstr;
    };

    mem_store  m_;
};

handler::handler()
    : pimpl_(new impl)
{ }

handler::~handler()
{
    delete pimpl_;
}

} // namespace crash_handler
