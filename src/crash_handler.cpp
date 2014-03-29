#include <iostream>

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
#include <csignal>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sys/types.h>
#include <sys/stat.h>
#include <functional>

#include "crash_handler.h"
#include "process_monitor.h"
#include "stack_explorer.h"


namespace crash_handler
{
using namespace process_monitor;

char const* const ERROR_MESSAGES[] = {
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

static char const    PREFIX[]   = "crash_";
static size_t const  PREFIX_LEN = 6;

static size_t const  DUMP_FILENAME_SIZE = 1024;
static size_t const  EXTRA_MESSAGE_SIZE = 4096;
static size_t const  STACK_BUF_SIZE     = 128;
static size_t const  TIME_BUF_SIZE      = 20;


void report_and_exit();

LONG WINAPI  catch_seh(PEXCEPTION_POINTERS pExceptionPtrs);
void __cdecl catch_invalid_parameter(wchar_t const* expression, wchar_t const* function,
                                     wchar_t const* file      , unsigned int   line,
                                     uintptr_t);
void __cdecl catch_terminate_unexpected_purecall();
void catch_signals(int code);
void fill_exception_pointers();
char const* const dump_filename();
void write_stacks(std::ostream& ostr);
void write_modules(std::ostream& ostr);

typedef void (*signal_handler_function_t)(int);

struct mem_store
{
    mem_store();

    int                           prev_crt_assert;
    int                           prev_crt_error;
    _purecall_handler             prev_purecall_handler;
    LPTOP_LEVEL_EXCEPTION_FILTER  prev_exception_filter;
    _invalid_parameter_handler    prev_invalid_param_handler;
    terminate_function            prev_terminate_func;
    signal_handler_function_t     prev_signal_handler;

    EXCEPTION_RECORD  exception_record;
    CONTEXT           exception_context;
    size_t            err_msg_index;
    thread_id_t       crashed_tid;
    wchar_t           wmsg[EXTRA_MESSAGE_SIZE / sizeof(wchar_t)];

    char              extra_message[EXTRA_MESSAGE_SIZE];
    char              dumpfile[DUMP_FILENAME_SIZE];

    size_t            name_len;
    size_t            suffix_len;

    time_t            time_t_buf;
    struct tm         tm_buf;

    stack_frame_t     stack_buf[STACK_BUF_SIZE];
    proc_id_t         cur_pid;
    HANDLE            hSnapshot;
    THREADENTRY32     te;
    CONTEXT*          cntx;
    MODULEENTRY32     mod_entry;
    char              time_buf[TIME_BUF_SIZE];
    std::ofstream     ofstr;

    char              stexp_place[sizeof(stack_explorer)];
};
static mem_store*  mem;

handler::handler()
{
    mem = new mem_store;

    using namespace std::placeholders;

    mem->prev_crt_assert = _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG); // remove assertion fail window
    mem->prev_crt_error  = _CrtSetReportMode(_CRT_ERROR , _CRTDBG_MODE_DEBUG); // remove debug error window

    mem->prev_purecall_handler = _set_purecall_handler(catch_terminate_unexpected_purecall); // catch pure virtual function call
    mem->prev_exception_filter = SetUnhandledExceptionFilter(catch_seh); // install SEH handler
    
    // must be declared before signal handlers
    mem->prev_invalid_param_handler = _set_invalid_parameter_handler(catch_invalid_parameter); // catch invalid parameter exception
    mem->prev_terminate_func        = set_terminate(catch_terminate_unexpected_purecall);      // catch terminate() calls.
    mem->prev_signal_handler        = signal(SIGABRT, catch_signals);                          // C++ signal handlers
}

handler::~handler()
{
    _CrtSetReportMode(_CRT_ASSERT, mem->prev_crt_assert);
    _CrtSetReportMode(_CRT_ERROR , mem->prev_crt_error);

    _set_purecall_handler      (mem->prev_purecall_handler);
    SetUnhandledExceptionFilter(mem->prev_exception_filter);

    _set_invalid_parameter_handler(mem->prev_invalid_param_handler);
    set_terminate                 (mem->prev_terminate_func);
    signal                        (SIGABRT, mem->prev_signal_handler);

    delete mem;
}

mem_store::mem_store()
{
    memset(&exception_record , 0, sizeof(exception_record ));
    memset(&exception_context, 0, sizeof(exception_context));
    memset(extra_message     , 0, EXTRA_MESSAGE_SIZE       );
    memset(wmsg              , 0, sizeof(wmsg)             );
    memset(dumpfile          , 0, DUMP_FILENAME_SIZE       );
    memset(&time_t_buf       , 0, sizeof(time_t_buf)       );
    memset(&tm_buf           , 0, sizeof(tm_buf)           );
    memset(stack_buf         , 0, STACK_BUF_SIZE           );
    memset(&te               , 0, sizeof(te)               );
    memset(&mod_entry        , 0, sizeof(mod_entry)        );
    memset(time_buf          , 0, TIME_BUF_SIZE            );
    memset(stexp_place       , 0, sizeof(stack_explorer)   );

    prev_crt_assert            = 0;
    prev_crt_error             = 0;
    prev_purecall_handler      = 0;
    prev_exception_filter      = 0;
    prev_invalid_param_handler = 0;
    prev_terminate_func        = 0;
    prev_signal_handler        = 0;

    err_msg_index = 0;
    crashed_tid   = 0;
    name_len      = 0;
    suffix_len    = 0;
    cur_pid       = 0;
    hSnapshot     = 0;
    cntx          = 0;
}

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

    mem->exception_record  = *pExceptionPtrs->ExceptionRecord;
    mem->exception_context = *pExceptionPtrs->ContextRecord;

    switch(mem->exception_record.ExceptionCode)
    {
    case EXCEPTION_ACCESS_VIOLATION:         mem->err_msg_index = 0;  break;
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    mem->err_msg_index = 1;  break;
    case EXCEPTION_BREAKPOINT:               mem->err_msg_index = 2;  break;
    case EXCEPTION_DATATYPE_MISALIGNMENT:    mem->err_msg_index = 3;  break;
    case EXCEPTION_FLT_DENORMAL_OPERAND:     mem->err_msg_index = 4;  break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:       mem->err_msg_index = 5;  break;
    case EXCEPTION_FLT_INEXACT_RESULT:       mem->err_msg_index = 6;  break;
    case EXCEPTION_FLT_INVALID_OPERATION:    mem->err_msg_index = 7;  break;
    case EXCEPTION_FLT_OVERFLOW:             mem->err_msg_index = 8;  break;
    case EXCEPTION_FLT_STACK_CHECK:          mem->err_msg_index = 9;  break;
    case EXCEPTION_FLT_UNDERFLOW:            mem->err_msg_index = 10; break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:      mem->err_msg_index = 11; break;
    case EXCEPTION_IN_PAGE_ERROR:            mem->err_msg_index = 12; break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:       mem->err_msg_index = 13; break;
    case EXCEPTION_INT_OVERFLOW:             mem->err_msg_index = 14; break;
    case EXCEPTION_INVALID_DISPOSITION:      mem->err_msg_index = 15; break;
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: mem->err_msg_index = 16; break;
    case EXCEPTION_PRIV_INSTRUCTION:         mem->err_msg_index = 17; break;
    case EXCEPTION_SINGLE_STEP:              mem->err_msg_index = 18; break;
    case EXCEPTION_STACK_OVERFLOW:           mem->err_msg_index = 19; break;
    default:
        mem->err_msg_index = 20;
        sprintf_s(mem->extra_message, EXTRA_MESSAGE_SIZE, "%u", mem->exception_record.ExceptionCode);
        break;
    }
    report_and_exit(); // no return from there
    
    return EXCEPTION_EXECUTE_HANDLER;
}

void __cdecl catch_invalid_parameter(wchar_t const* expression, wchar_t const* function,
                                     wchar_t const* file      , unsigned int   line,
                                     uintptr_t)
{
    mem->err_msg_index = 21;
    swprintf_s(mem->wmsg, EXTRA_MESSAGE_SIZE, L"Func: %s. File: %s. Line: %d. Expression: %s", function, file, line, expression);
    memcpy(mem->extra_message, mem->wmsg, EXTRA_MESSAGE_SIZE);
    report_and_exit();
}

void __cdecl catch_terminate_unexpected_purecall()
{
    mem->err_msg_index = 22;
    
    // this call allows to get some stack info in Release configuration
    RaiseException(0, 0, 0, NULL);
}

void catch_signals(int code)
{
    mem->err_msg_index = 23;
    report_and_exit();
}

void fill_exception_pointers()
{
    static EXCEPTION_RECORD & exception_record  = mem->exception_record;
    static CONTEXT          & exception_context = mem->exception_context;

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
    memset(mem->dumpfile, 0     , DUMP_FILENAME_SIZE);
    memcpy(mem->dumpfile, PREFIX, PREFIX_LEN        );

    static size_t const buf_size = 1024;
    static char buf[buf_size];
    memset(buf, 0, buf_size);

    mem->name_len = GetModuleFileName(NULL, buf, buf_size);
    static char const* basename = strrchr(buf, '\\') + 1;
    mem->name_len -= (basename - buf);
    memcpy(mem->dumpfile + PREFIX_LEN, basename, DUMP_FILENAME_SIZE - PREFIX_LEN);

    DWORD last_err = GetLastError();

    mem->suffix_len = DUMP_FILENAME_SIZE - (PREFIX_LEN + mem->name_len);
    if (19 < mem->suffix_len)
        mem->suffix_len = 19;

    mem->time_t_buf = time(NULL);
    localtime_s(&mem->tm_buf, &mem->time_t_buf);
    strftime(mem->dumpfile + PREFIX_LEN + mem->name_len, mem->suffix_len, "_%Y-%m-%d_%H%M%S", &mem->tm_buf);

    return mem->dumpfile;
}

void write_stacks(std::ostream& ostr)
{
    mem->cur_pid = current_process_id();
    static stack_explorer* stexp = new(mem->stexp_place) stack_explorer(mem->cur_pid);

    ostr << "==============" << std::endl;
    ostr << "Threads Stacks" << std::endl;
    ostr << "==============" << std::endl;
    ostr << "RVA\tFunction\tFile:Line" << std::endl;

    mem->hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, mem->cur_pid);
    if (mem->hSnapshot != INVALID_HANDLE_VALUE)
    {
        mem->te.dwSize = sizeof(mem->te);
        if (Thread32First(mem->hSnapshot, &mem->te))
        {
            do
            {
                if (mem->te.th32OwnerProcessID == mem->cur_pid)
                {
                    mem->cntx = NULL;
                    if (mem->te.th32ThreadID == mem->crashed_tid)
                        mem->cntx = &mem->exception_context;
                    stexp->thread_stack(mem->te.th32ThreadID, mem->stack_buf, STACK_BUF_SIZE, mem->cntx);

                    ostr << std::endl;
                    ostr << "Thread id: " << mem->te.th32OwnerProcessID << std::endl;
                    ostr << "Stack:" << std::endl;
                    for (static size_t k = 0; k < STACK_BUF_SIZE; ++k)
                    {
                        static stack_frame_t const* stf = (mem->stack_buf + k);
                        if (0 == stf)
                            break;
                        ostr << std::hex     << std::right << std::setw(8) << std::setfill('0')
                            << stf->address  << "\t"       << std::dec     << std::left
                            << stf->function << "()\t"     << stf->file    << ":"
                            << stf->line     << std::endl;
                    }
                }
                mem->te.dwSize = sizeof(mem->te);
            }
            while (Thread32Next(mem->hSnapshot, &mem->te));
        }
        CloseHandle(mem->hSnapshot);
    }
    else
        ostr << "CreateToolhelp32Snapshot failed" << std::endl;

    ostr << "==============" << std::endl;

    ostr.flush();

    // TODO: not sure if this is a good idea
    stexp->~stack_explorer();
}

void write_modules(std::ostream& ostr)
{
    mem->mod_entry.dwSize = sizeof(mem->mod_entry);

    mem->cur_pid = current_process_id();
    mem->hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, mem->cur_pid);
    if (mem->hSnapshot == INVALID_HANDLE_VALUE)
        return;

    ostr << "==============" << std::endl << "Loaded Modules" << std::endl << "==============" << std::endl;

    Module32First(mem->hSnapshot, &mem->mod_entry);
    do
    {
        ostr << mem->mod_entry.szModule << std::endl << "\t" << mem->mod_entry.szExePath << std::endl << mem->mod_entry.modBaseAddr << std::endl;
        static int64_t mtime = 0;
        static struct _stat file_stat;
        if (!_stat(mem->mod_entry.szExePath, &(file_stat)))
            mtime = file_stat.st_mtime;

#ifdef _WIN32
        localtime_s(&mem->tm_buf, &mem->time_t_buf);
#elif __linux__
        memcpy(&mem->tm_buf, localtime(&mem->time_t_buf), sizeof(mem->tm_buf));
#endif
        strftime(mem->time_buf, TIME_BUF_SIZE, "%Y-%m-%d %H:%M:%S", &mem->tm_buf);
        ostr << "\t" << mem->time_buf << std::endl;
    }
    while (Module32Next(mem->hSnapshot, &mem->mod_entry));
    CloseHandle(mem->hSnapshot);
}

void report_and_exit()
{
    int tmp_var;
    std::cin >> tmp_var;

    if (mem->exception_record.ExceptionAddress == NULL)
        fill_exception_pointers();

    mem->ofstr.open(dump_filename());

    mem->ofstr << ERROR_MESSAGES[mem->err_msg_index] << "\n";
    mem->ofstr << mem->extra_message << "\n";
    mem->ofstr << "Crashed thread: " << GetCurrentThreadId() << "\n";

    write_stacks (mem->ofstr);
    write_modules(mem->ofstr);

    mem->ofstr.close();

    if (IsDebuggerPresent())
        __debugbreak();

    TerminateProcess(GetCurrentProcess(), 1);
}

} // namespace crash_handler
