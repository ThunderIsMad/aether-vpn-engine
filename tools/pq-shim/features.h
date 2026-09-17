/* Shim for PQClean compat.h on MinGW: provides glibc's __GNUC_PREREQ. */
#ifndef _SHIM_FEATURES_H
#define _SHIM_FEATURES_H
#define __GNUC_PREREQ(maj, min) \
  ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#endif
