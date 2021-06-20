#include "host.h"

#if !OC_IDENT_INLINE
uint32_t makeIdent(const char *text)
{
	char a = text[0];
	char b = text[1];
	char c = text[2];
	char d = text[3];
	return (a << 24 | b << 16 | c << 8 | d);
}
#endif