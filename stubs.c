// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Dummy functions for parts of FRR we're not linking in here
 */

#include "config.h"
#include "compiler.h"

#include <assert.h>
#include "xref.h"
#include "printfrr.h"
#include "zlog.h"

PRINTFRR(3, 0)
void vzlogx(const struct xref_logmsg *xref, int prio,
	    const char *format, va_list args)
{
	vfprintf(stderr, format, args);
	fputs("\n", stderr);
}

void _zlog_assert_failed(const struct xref_assert *xref, const char *extra, ...)
{
	char *out;

	out = asprintfrr(MTYPE_TMP, "%s:%d: assert(%s) failed",
			 xref->xref.file, xref->xref.line, xref->expr);
	fputs(out, stderr);

	if (extra) {
		va_list ap;

		fputs(" [", stderr);
		va_start(ap, extra);
		out = vasprintfrr(MTYPE_TMP, extra, ap);
		fputs(out, stderr);
		fputs("]", stderr);
		va_end(ap);
	}
	fputs("\n", stderr);
	abort();
}

void memory_oom(size_t size, const char *name)
{
	abort();
}

const char *safe_strerror(int err)
{
	return strerror(err) ?: "???";
}

bool cmd_allow_reserved_ranges_get(void)
{
	return false;
}
