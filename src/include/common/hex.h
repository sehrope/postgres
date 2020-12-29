/*
 *	hex.h
 *		hex processing
 *
 *	Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
 *	Portions Copyright (c) 1994, Regents of the University of California
 *
 *	src/include/common/hex.h
 */
#ifndef COMMON_HEX_H
#define COMMON_HEX_H

extern uint64 hex_decode(const char *src, size_t len, char *dst);


#endif							/* COMMON_HEX_H */
