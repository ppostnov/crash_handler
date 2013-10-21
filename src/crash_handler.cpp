#include <Windows.h>
#include <crtdbg.h>
#include <csignal>
#include <cstdio>
#include <ctime>
#include <exception>
#include <fstream>

#include "crash_handler.h"


namespace crash_handler
{
char const* const error_messages[] = {
    "Access violation",             // 0
    "Array bounds exceeded",
    "Breakpoint was encountered",
    "Datatype misalignment",
    "Float: Denormal operand",
    "Float: Divide by zero",        // 5
    "Float: Inexact result",
    "Float: Invalid operation",
    "Float: Overflow",
    "Float: Stack check",
    "Float: Underflow",             // 10
    "Illegal instruction",
    "Page error",
    "Integer: Divide by zero",
    "Integer: Overflow",
    "Invalid disposition",          // 15
    "Noncontinuable exception",
    "Private Instruction",
    "Single step",
    "Stack overflow",
    "Unknown exception code",       // 20
    "Invalid CRT parameter",
    "A call to terminate()/unexpected() or pure virtual call",
    "SIGABRT caught"};

static EXCEPTION_RECORD  exception_record;
static CONTEXT           exception_context;
static size_t            err_msg_index = 0;

size_t const  extra_message_size = 4096;
static char   extra_message[extra_message_size];

void report_and_exit();

LONG WINAPI catch_seh(PEXCEPTION_POINTERS pExceptionPtrs)
{
    if (pExceptionPtrs->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW)
    {
        static char MyStack[1024 * 128];  // be sure that we have enough space...
        // it assumes that DS and SS are the same!!! (this is the case for Win32)
        // change the stack only if the selectors are the same (this is the case for Win32)
#ifdef _M_IX86
        __asm mov eax, offset MyStack[1024 * 128];
        __asm mov esp, eax;
#elif _M_X64
        __asm mov rax, offset MyStack[1024 * 128];
        __asm mov rsp, rax;
#endif
    }

    exception_record  = *pExceptionPtrs->ExceptionRecord;
    exception_context = *pExceptionPtrs->ContextRecord;

    switch(exception_record.ExceptionCode)
    {
    case EXCEPTION_ACCESS_VIOLATION:         err_msg_index = 0;  break;
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    err_msg_index = 1;  break;
    case EXCEPTION_BREAKPOINT:               err_msg_index = 2;  break;
    case EXCEPTION_DATATYPE_MISALIGNMENT:    err_msg_index = 3;  break;
    case EXCEPTION_FLT_DENORMAL_OPERAND:     err_msg_index = 4;  break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:       err_msg_index = 5;  break;
    case EXCEPTION_FLT_INEXACT_RESULT:       err_msg_index = 6;  break;
    case EXCEPTION_FLT_INVALID_OPERATION:    err_msg_index = 7;  break;
    case EXCEPTION_FLT_OVERFLOW:             err_msg_index = 8;  break;
    case EXCEPTION_FLT_STACK_CHECK:          err_msg_index = 9;  break;
    case EXCEPTION_FLT_UNDERFLOW:            err_msg_index = 10; break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:      err_msg_index = 11; break;
    case EXCEPTION_IN_PAGE_ERROR:            err_msg_index = 12; break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:       err_msg_index = 13; break;
    case EXCEPTION_INT_OVERFLOW:             err_msg_index = 14; break;
    case EXCEPTION_INVALID_DISPOSITION:      err_msg_index = 15; break;
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: err_msg_index = 16; break;
    case EXCEPTION_PRIV_INSTRUCTION:         err_msg_index = 17; break;
    case EXCEPTION_SINGLE_STEP:              err_msg_index = 18; break;
    case EXCEPTION_STACK_OVERFLOW:           err_msg_index = 19; break;
    default:
        err_msg_index = 20;
        sprintf_s(extra_message, extra_message_size, "%u", exception_record.ExceptionCode);
        break;
    }
    report_and_exit(); // no return from there
    
    return EXCEPTION_EXECUTE_HANDLER;
}

void __cdecl catch_invalid_parameter(wchar_t const* expression, wchar_t const* function,
                                     wchar_t const* file      , unsigned int   line,
                                     uintptr_t)
{
    err_msg_index = 21;
    static wchar_t wmsg[extra_message_size / sizeof(wchar_t)];

    swprintf_s(wmsg, extra_message_size, L"Func: %s. File: %s. Line: %d. Expression: %s", function, file, line, expression);
    memcpy(extra_message, wmsg, extra_message_size);
    report_and_exit();
}

void __cdecl catch_terminate_unexpected_purecall()
{
    err_msg_index = 22;
    
    // this call allows to get some stack info in Release configuration
    RaiseException(0, 0, 0, NULL);
}

void catch_signals(int code)
{
    err_msg_index = 23;
    report_and_exit();
}

void fill_exception_pointers()
{
    memset(&exception_context, 0, sizeof(CONTEXT));
    exception_context.ContextFlags = CONTEXT_FULL;

#ifdef _X86_
    RtlCaptureContext(&exception_context);
#elif defined (_IA64_) || defined (_AMD64_)
    /* Need to fill up the Context in IA64 and AMD64. */
    RtlCaptureContext(&exception_context);
#else  /* defined (_IA64_) || defined (_AMD64_) */
    ZeroMemory(&exception_context, sizeof(exception_context));
#endif  /* defined (_IA64_) || defined (_AMD64_) */

    memset(&exception_record, 0, sizeof(EXCEPTION_RECORD));
#ifdef _M_IX86
    exception_record.ExceptionAddress = (PVOID)exception_context.Eip;
#elif _M_X64
    exception_record.ExceptionAddress = (PVOID)exception_context.Rip;
#elif _M_IA64
    exception_record.ExceptionAddress = (PVOID)exception_context.StIIP;
#endif  
}

char const* const dump_filename()
{
    static char const   prefix[]   = "crash_";
    static size_t const prefix_len = sizeof(prefix) / sizeof(char);
    
    static size_t const dump_filename_size = 1024;
    static char         dumpfile[dump_filename_size];
    
    memset(dumpfile, 0, dump_filename_size);
    memcpy(dumpfile, prefix, prefix_len);

    static size_t const name_len = GetModuleFileName(NULL, dumpfile + 12, 1012);
    
    static size_t suffix_len = dump_filename_size - (prefix_len + name_len);
    if (18 < suffix_len)
        suffix_len = 18;

    time_t const cur_time = time(NULL);
    struct tm cur_tm;
    localtime_s(&cur_tm, &cur_time);
    strftime(dumpfile + prefix_len + name_len, suffix_len, "%Y-%m-%d_%H%M%S", &cur_tm);
    
    return dumpfile;
}

void write_stacks(std::ostream& ostr)
{
    static size_t const   stack_buf_size = 128;
    static stack_frame_t  stack_buf[stack_buf_size];

    proc_id_t cur_pid = current_process_id();
    stack_explorer stexp(cur_pid);

    static HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, cur_pid);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        static THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(hSnapshot, &te))
        {
            do
            {
                if (te.th32OwnerProcessID == cur_pid)
                {
                    CONTEXT* cntx = NULL;
                    if (te.th32ThreadID == crashed_thread_)
                        cntx = exception_ptrs_.ContextRecord;
                    stackwalker.thread_stack(te.th32ThreadID, stack_buf, stack_buf_size, cntx);
                    // TODO: print stack to ostream
                }
                te.dwSize = sizeof(te);
            }
            while (Thread32Next(hSnapshot, &te));
        }
        CloseHandle(hSnapshot);
    }
    else
        ostr << "CreateToolhelp32Snapshot failed" << std::endl;
    //ostr << "==============" << std::endl;
    //ostr << "Threads Stacks" << std::endl;
    //ostr << "==============" << std::endl;
    //ostr << "RVA\tFunction\tFile:Line" << std::endl << std::endl;
    for (process_state::proc_stack::const_iterator pit = stack.begin(); pit != stack.end(); ++pit)
    {
        if (pit != stack.begin())
            ostr << std::endl;
        ostr << "Thread id: " << pit->first << std::endl;
        ostr << "Stack:" << std::endl;
        for (process_state::thread_stack::const_iterator tit = pit->second.begin();
            tit != pit->second.end(); ++tit)
        {
            ostr << std::hex      << std::right << std::setw(8) << std::setfill('0')
                << tit->address  << "\t"       << std::dec     << std::left
                << tit->function << "()\t"     << tit->file    << ":"
                << tit->line     << std::endl;
        }
    }
    ostr << "==============" << std::endl;

    ostr.flush();
}

void write_modules(std::ostream& ostr)
{
}

void report_and_exit()
{
    if (exception_record.ExceptionAddress == NULL)
        fill_exception_pointers();

    static std::ofstream ofstr;
    ofstr.open(dump_filename());

    ofstr << error_messages[err_msg_index] << "\n";
    ofstr << extra_message << "\n";
    ofstr << "Crashed thread: " << GetCurrentThreadId() << "\n";
    
    write_stacks (ofstr);
    write_modules(ofstr);
    
    ofstr.close();

    if (IsDebuggerPresent())
        __debugbreak();
    
    TerminateProcess(GetCurrentProcess(), 1);
}

void create_handler()
{
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);      // remove assertion fail window
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);       //  remove debug error window

    _set_purecall_handler(catch_terminate_unexpected_purecall);        // catch pure virtual function call
    SetUnhandledExceptionFilter(catch_seh);                  // install SEH handler
    
    // must be declared before signal handlers
    _set_invalid_parameter_handler(catch_invalid_parameter); // catch invalid parameter exception
    set_terminate(catch_terminate_unexpected_purecall);      // catch terminate() calls.
    signal(SIGABRT, catch_signals);                          // C++ signal handlers

    memset(&exception_record , 0, sizeof(exception_record ));
    memset(&exception_context, 0, sizeof(exception_context));
    memset(extra_message, 0, extra_message_size);
}

} // namespace crash_handler
