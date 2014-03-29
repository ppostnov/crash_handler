#pragma once

#if defined _WIN32 || defined __CYGWIN__
#   define DEF_IMPORT __declspec(dllimport)
#   define DEF_EXPORT __declspec(dllexport)
#   define DEF_LOCAL
#   pragma warning (disable:4251)
#else
#   if __GNUC__ >= 4
#      define DEF_IMPORT
#      define DEF_EXPORT __attribute__((used, visibility ("default")))
#      define DEF_LOCAL  __attribute__ ((visibility ("hidden")))
#   else
#      define DEF_IMPORT
#      define DEF_EXPORT
#      define DEF_LOCAL
#   endif
#endif

#ifdef CRASH_HANDLER_LIB
#   define MACRO_API DEF_EXPORT
#else
#   define MACRO_API DEF_IMPORT
#endif

