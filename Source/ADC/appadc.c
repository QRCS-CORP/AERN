#include "appadc.h"
#include "adc.h"

int main(void)
{
	int32_t ret;

	ret = aern_adc_start_server();

	return ret;
}
