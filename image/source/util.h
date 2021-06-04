#pragma once

#define OC_ARRAYSIZE(x) \
	(sizeof((x)) / sizeof((x)[0]))

#define OC_HANG() \
	while (1)

#define OC_CONCAT_IMPL(s1, s2) s1##s2
#define OC_CONCAT(s1, s2) OC_CONCAT_IMPL(s1, s2)
#define OC_ANONYMOUS(str) OC_CONCAT(str, __LINE__)

#define OC_INIT_FUNCTION() \
	static void OC_ANONYMOUS(oc_if_func)(); \
	static InitFunctionReg OC_ANONYMOUS(oc_if_obj)(OC_ANONYMOUS(oc_if_func)); \
	static void OC_ANONYMOUS(oc_if_func)()

using PFN_InitFunction = void (*)();

struct InitFunctionReg
{
	InitFunctionReg(PFN_InitFunction fn)
	{
		func = fn;
		pNext = s_pFirst;
		s_pFirst = this;
	}

	PFN_InitFunction func;
	InitFunctionReg *pNext;
	static InitFunctionReg *s_pFirst;
};

bool base64Decode(const char *text, void **out_buf, int *out_len);