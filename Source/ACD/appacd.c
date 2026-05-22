#include "appacd.h"
#include "client.h"

int main(void)
{
	int32_t ret;

	ret = aern_client_start();

	return ret;
}
