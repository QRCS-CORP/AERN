#include "appars.h"
#include "ars.h"
#if defined(AERN_DEBUG_TESTS_RUN)
#	include "collection.h"
#	include "consoleutils.h"
#	include "certificate.h"
#	include "mpdc.h"
#endif

int main(void)
{
	aern_ars_start_server();

	return 0;
}
