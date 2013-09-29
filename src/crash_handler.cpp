#include <Windows.h>
#include <crtdbg.h>
#include <csignal>
#include <cstdio>
#include <exception>

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

static EXCEPTION_POINTERS  exception_ptrs;
static size_t              exc_msg_index = 0;

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

    exception_ptrs.ExceptionRecord = pExceptionPtrs->ExceptionRecord;
    exception_ptrs.ContextRecord   = pExceptionPtrs->ContextRecord;

    switch(exception_ptrs.ExceptionRecord->ExceptionCode)
    {
    case EXCEPTION_ACCESS_VIOLATION:         exc_msg_index = 0;  break;
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    exc_msg_index = 1;  break;
    case EXCEPTION_BREAKPOINT:               exc_msg_index = 2;  break;
    case EXCEPTION_DATATYPE_MISALIGNMENT:    exc_msg_index = 3;  break;
    case EXCEPTION_FLT_DENORMAL_OPERAND:     exc_msg_index = 4;  break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:       exc_msg_index = 5;  break;
    case EXCEPTION_FLT_INEXACT_RESULT:       exc_msg_index = 6;  break;
    case EXCEPTION_FLT_INVALID_OPERATION:    exc_msg_index = 7;  break;
    case EXCEPTION_FLT_OVERFLOW:             exc_msg_index = 8;  break;
    case EXCEPTION_FLT_STACK_CHECK:          exc_msg_index = 9;  break;
    case EXCEPTION_FLT_UNDERFLOW:            exc_msg_index = 10; break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:      exc_msg_index = 11; break;
    case EXCEPTION_IN_PAGE_ERROR:            exc_msg_index = 12; break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:       exc_msg_index = 13; break;
    case EXCEPTION_INT_OVERFLOW:             exc_msg_index = 14; break;
    case EXCEPTION_INVALID_DISPOSITION:      exc_msg_index = 15; break;
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: exc_msg_index = 16; break;
    case EXCEPTION_PRIV_INSTRUCTION:         exc_msg_index = 17; break;
    case EXCEPTION_SINGLE_STEP:              exc_msg_index = 18; break;
    case EXCEPTION_STACK_OVERFLOW:           exc_msg_index = 19; break;
    default:
        exc_msg_index = 20;
        sprintf_s(extra_message, extra_message_size, "%u", exception_ptrs.ExceptionRecord->ExceptionCode);
        break;
    }
    report_and_exit(); // no return from there
    
    return EXCEPTION_EXECUTE_HANDLER;
}

void __cdecl catch_invalid_parameter(wchar_t const* expression, wchar_t const* function,
                                     wchar_t const* file      , unsigned int   line,
                                     uintptr_t)
{
    exc_msg_index = 21;
    static wchar_t wmsg[extra_message_size / sizeof(wchar_t)];

    swprintf_s(wmsg, extra_message_size, L"Func: %s. File: %s. Line: %d. Expression: %s", function, file, line, expression);
    memcpy(extra_message, wmsg, extra_message_size);
    report_and_exit();
}

void __cdecl catch_terminate_unexpected_purecall()
{
    exc_msg_index = 22;
    
    /// this call somehow allows to get some stack info in Release configuration
    RaiseException(0, 0, 0, NULL);
}

void catch_signals(int code)
{
    exc_msg_index = 23;
    report_and_exit();
}

void report_and_exit()
{
}

ch::ch()
{
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);      // remove assertion fail window
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);       //  remove debug error window

    _set_purecall_handler(catch_terminate_unexpected_purecall);        // catch pure virtual function call
    SetUnhandledExceptionFilter(catch_seh);                  // install SEH handler
    
    // must be declared before signal handlers
    _set_invalid_parameter_handler(catch_invalid_parameter); // catch invalid parameter exception
    set_terminate(catch_terminate_unexpected_purecall);      // catch terminate() calls.
    signal(SIGABRT, catch_signals);                          // C++ signal handlers

    memset(&exception_ptrs, 0, sizeof(exception_ptrs));
    memset(extra_message, 0, extra_message_size);
}

} // namespace crash_handler
