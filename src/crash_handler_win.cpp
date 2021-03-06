
#include <csignal>
#include <fstream>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "DbgHelp.lib")

#include "crash_handler.h"
#include "crash_handler_impl.h"
#include "stack_explorer.h"
#include "util.h"


namespace crash_handler
{

static uint16_t const  EXTRA_MESSAGE_SIZE = 4096;

static EXCEPTION_RECORD  exception_record;
static CONTEXT           exception_context;
static char              extra_message[EXTRA_MESSAGE_SIZE];
static uint16_t          err_code;

static handler::impl*    glob_impl;


void fill_exception_pointers()
{
    static EXCEPTION_RECORD& exception_record  = exception_record;
    static CONTEXT         & exception_context = exception_context;

    memset(&exception_context, 0, sizeof(CONTEXT));
    exception_context.ContextFlags = CONTEXT_FULL;

#ifdef _X86_
    RtlCaptureContext(&exception_context);
#elif defined (_IA64_) || defined (_AMD64_)
    // Need to fill up the Context in IA64 and AMD64.
    RtlCaptureContext(&exception_context);
#else  // defined (_IA64_) || defined (_AMD64_)
    ZeroMemory(&exception_context, sizeof(exception_context));
#endif  // defined (_IA64_) || defined (_AMD64_)

    memset(&exception_record, 0, sizeof(EXCEPTION_RECORD));
#ifdef _M_IX86
    exception_record.ExceptionAddress = (PVOID)exception_context.Eip;
#elif _M_X64
    exception_record.ExceptionAddress = (PVOID)exception_context.Rip;
#elif _M_IA64
    exception_record.ExceptionAddress = (PVOID)exception_context.StIIP;
#endif
}

LONG WINAPI catch_seh(PEXCEPTION_POINTERS pExceptionPtrs)
{
//    if (pExceptionPtrs->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW)
//    {
//        static char MyStack[1024 * 128];  // be sure that we have enough space...
//        // it assumes that DS and SS are the same!!! (this is the case for Win32)
//        // change the stack only if the selectors are the same (this is the case for Win32)
//#ifdef _M_IX86
//        __asm mov eax, offset MyStack[1024 * 128];
//        __asm mov esp, eax;
//#elif _M_X64
//        __asm mov rax, offset MyStack[1024 * 128];
//        __asm mov rsp, rax;
//#endif
//    }

    exception_record  = *pExceptionPtrs->ExceptionRecord;
    exception_context = *pExceptionPtrs->ContextRecord;

    switch(exception_record.ExceptionCode)
    {
    case EXCEPTION_ACCESS_VIOLATION:         err_code = 0;  break;
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    err_code = 1;  break;
    case EXCEPTION_BREAKPOINT:               err_code = 2;  break;
    case EXCEPTION_DATATYPE_MISALIGNMENT:    err_code = 3;  break;
    case EXCEPTION_FLT_DENORMAL_OPERAND:     err_code = 4;  break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:       err_code = 5;  break;
    case EXCEPTION_FLT_INEXACT_RESULT:       err_code = 6;  break;
    case EXCEPTION_FLT_INVALID_OPERATION:    err_code = 7;  break;
    case EXCEPTION_FLT_OVERFLOW:             err_code = 8;  break;
    case EXCEPTION_FLT_STACK_CHECK:          err_code = 9;  break;
    case EXCEPTION_FLT_UNDERFLOW:            err_code = 10; break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:      err_code = 11; break;
    case EXCEPTION_IN_PAGE_ERROR:            err_code = 12; break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:       err_code = 13; break;
    case EXCEPTION_INT_OVERFLOW:             err_code = 14; break;
    case EXCEPTION_INVALID_DISPOSITION:      err_code = 15; break;
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: err_code = 16; break;
    case EXCEPTION_PRIV_INSTRUCTION:         err_code = 17; break;
    case EXCEPTION_SINGLE_STEP:              err_code = 18; break;
    case EXCEPTION_STACK_OVERFLOW:           err_code = 19; break;
    default:
        err_code = exception_record.ExceptionCode;
        break;
    }
    glob_impl->report_and_exit(); // no return from there

    return EXCEPTION_EXECUTE_HANDLER;
}

void __cdecl catch_invalid_parameter(wchar_t const* expression, wchar_t const* function,
                                     wchar_t const* file      , unsigned int   line,
                                     uintptr_t)
{
    err_code = 21;
    swprintf_s((wchar_t*)extra_message, EXTRA_MESSAGE_SIZE / sizeof(wchar_t), L"Func: %s. File: %s. Line: %d. Expression: %s", function, file, line, expression);

    fill_exception_pointers();
    glob_impl->report_and_exit();
}

void __cdecl catch_terminate_unexpected_purecall()
{
    err_code = 22;

    // this call allows to get some stack info in Release configuration
    RaiseException(0, 0, 0, NULL);
}

void catch_signals(int code)
{
    err_code = 23;
    fill_exception_pointers();
    glob_impl->report_and_exit();
}

void win_impl::get_context()
{
    info.code = (error_code)err_code;
}

void win_impl::get_stack()
{
    thread_num = 0;

    hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, info.pid);
    if (hProc == NULL)
        return;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, info.pid);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        CloseHandle(hProc);
        return;
    }

    te.dwSize = sizeof(te);
    if (Thread32First(hSnapshot, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == info.pid)
            {
                hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                     FALSE, te.th32ThreadID);

                if (hThread == NULL)
                    continue;

                if (te.th32ThreadID != current_thread_id())
                {
                    if (SuspendThread(hThread) == -1)
                    {
                        CloseHandle(hThread);
                        continue;
                    }

                }

                if (te.th32ThreadID == info.crashed_tid)
                    cntx = exception_context;
                else
                {
                    cntx.ContextFlags = CONTEXT_FULL;

                    if (te.th32ThreadID == current_thread_id())
                        RtlCaptureContext(&cntx);
                    else
                    {
                        if (!GetThreadContext(hThread, &cntx)) // this function doesn't work for current thread
                        {
                            CloseHandle(hThread);
                            continue;
                        }
                    }
                }

#ifdef _M_IX86
                // normally, call ImageNtHeader() and use machine info from PE header
                image_type = IMAGE_FILE_MACHINE_I386;
                stack_frame.AddrPC.Offset    = cntx.Eip;
                stack_frame.AddrPC.Mode      = AddrModeFlat;
                stack_frame.AddrFrame.Offset = cntx.Ebp;
                stack_frame.AddrFrame.Mode   = AddrModeFlat;
                stack_frame.AddrStack.Offset = cntx.Esp;
                stack_frame.AddrStack.Mode   = AddrModeFlat;
#elif _M_X64
                image_type = IMAGE_FILE_MACHINE_AMD64;
                stack_frame.AddrPC.Offset    = cntx.Rip;
                stack_frame.AddrPC.Mode      = AddrModeFlat;
                stack_frame.AddrFrame.Offset = cntx.Rsp;
                stack_frame.AddrFrame.Mode   = AddrModeFlat;
                stack_frame.AddrStack.Offset = cntx.Rsp;
                stack_frame.AddrStack.Mode   = AddrModeFlat;
#elif _M_IA64
                image_type = IMAGE_FILE_MACHINE_IA64;
                stack_frame.AddrPC.Offset     = cntx.StIIP;
                stack_frame.AddrPC.Mode       = AddrModeFlat;
                stack_frame.AddrFrame.Offset  = cntx.IntSp;
                stack_frame.AddrFrame.Mode    = AddrModeFlat;
                stack_frame.AddrBStore.Offset = cntx.RsBSP;
                stack_frame.AddrBStore.Mode   = AddrModeFlat;
                stack_frame.AddrStack.Offset  = cntx.IntSp;
                stack_frame.AddrStack.Mode    = AddrModeFlat;
#else
#   error "Platform not supported!"
#endif

                for (frame_num = 0; frame_num < STACK_SIZE; ++frame_num)
                {
                    // get next stack frame (StackWalk64(), SymFunctionTableAccess64(), SymGetModuleBase64())
                    // if this returns ERROR_INVALID_ADDRESS (487) or ERROR_NOACCESS (998), you can
                    // assume that either you are done, or that the stack is so hosed that the next
                    // deeper frame could not be found.
                    // CONTEXT need not to be supplied if image_type is IMAGE_FILE_MACHINE_I386!
                    if (!StackWalk64(image_type, hProc, hThread, &stack_frame, &cntx, NULL,
                                      &SymFunctionTableAccess64, &SymGetModuleBase64, NULL))
                        break;

                    if (stack_frame.AddrPC.Offset != 0)
                    {
                        frame = &info.stack[thread_num][frame_num];

                        module_start_address = SymGetModuleBase64(hProc, stack_frame.AddrPC.Offset);

                        if (module_start_address != 0)
                            frame->address = stack_frame.AddrPC.Offset - module_start_address; // current instruction of the function
                        else
                            frame->address = 0;
                    }
                }

                if (te.th32ThreadID != current_thread_id())
                    ResumeThread(hThread);
                CloseHandle(hThread);

                ++thread_num;
            }
            te.dwSize = sizeof(te);
        }
        while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    CloseHandle(hProc);
}

/****
void write_modules(std::ostream& ostr)
{
    mod_entry.dwSize = sizeof(mod_entry);

    cur_pid = current_process_id();
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, cur_pid);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return;

    ostr << "==============" << std::endl << "Loaded Modules" << std::endl << "==============" << std::endl;

    Module32First(hSnapshot, &mod_entry);
    do
    {
        ostr << mod_entry.szModule << std::endl << "\t" << mod_entry.szExePath << std::endl << mod_entry.modBaseAddr << std::endl;
        static int64_t mtime = 0;
        static struct _stat file_stat;
        if (!_stat(mod_entry.szExePath, &(file_stat)))
            mtime = file_stat.st_mtime;

#ifdef _WIN32
        localtime_s(&tm_buf, &time_t_buf);
#elif __linux__
        memcpy(&tm_buf, localtime(&time_t_buf), sizeof(tm_buf));
#endif
        strftime(time_buf, TIME_BUF_SIZE, "%Y-%m-%d %H:%M:%S", &tm_buf);
        ostr << "\t" << time_buf << std::endl;
    }
    while (Module32Next(hSnapshot, &mod_entry));
    CloseHandle(hSnapshot);
}
****/

win_impl::win_impl(primary_handler_f const* hp)
    : handler::impl(hp)
{
    memset(&exception_record , 0, sizeof(exception_record ));
    memset(&exception_context, 0, sizeof(exception_context));
    memset(extra_message     , 0, EXTRA_MESSAGE_SIZE       );
    //memset(&mod_entry        , 0, sizeof(mod_entry        ));
    memset(&cntx             , 0, sizeof(cntx             ));

    prev_crt_assert            = 0;
    prev_crt_error             = 0;
    prev_purecall_handler      = 0;
    prev_exception_filter      = 0;
    prev_invalid_param_handler = 0;
    prev_terminate_func        = 0;
    prev_signal_handler        = 0;

    err_code    = 0;
    hSnapshot   = 0;
    hProc       = 0;
    hThread     = 0;
}

win_impl::~win_impl()
{
    remove_handlers();
}

void win_impl::install_handlers()
{
    glob_impl = this;

    prev_crt_assert = _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG); // remove assertion fail window
    prev_crt_error  = _CrtSetReportMode(_CRT_ERROR , _CRTDBG_MODE_DEBUG); // remove debug error window

    prev_purecall_handler = _set_purecall_handler(catch_terminate_unexpected_purecall); // catch pure virtual function call
    prev_exception_filter = SetUnhandledExceptionFilter(catch_seh); // install SEH handler

    // must be declared before signal handlers
    prev_invalid_param_handler = _set_invalid_parameter_handler(catch_invalid_parameter); // catch invalid parameter exception
    prev_terminate_func        = set_terminate(catch_terminate_unexpected_purecall);      // catch terminate() calls.
    prev_signal_handler        = signal(SIGABRT, catch_signals);                          // C++ signal handlers
}

void win_impl::remove_handlers()
{
    glob_impl = nullptr; // TODO: maybe preserve old value

    _CrtSetReportMode(_CRT_ASSERT, prev_crt_assert);
    _CrtSetReportMode(_CRT_ERROR , prev_crt_error);

    _set_purecall_handler      (prev_purecall_handler);
    SetUnhandledExceptionFilter(prev_exception_filter);

    _set_invalid_parameter_handler(prev_invalid_param_handler);
    set_terminate                 (prev_terminate_func);
    signal                        (SIGABRT, prev_signal_handler);
}


} // namespace crash_handler
