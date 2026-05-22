#include "aern_utils.h"
#include "consoleutils.h"
#include "memutils.h"

#include <stdio.h>

char aerntest_get_char(void)
{
	char line[8U] = { 0 };
	char res;

	res = 0;

	if (fgets(line, sizeof(line), stdin) != NULL)
	{
		res = line[0U];
	}

	return res;
}

char aerntest_get_wait(void)
{
	char res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (char)getwchar();
#else
	res = (char)getchar();
#endif

	return res;
}

void aerntest_hex_to_bin(const char* hexstr, uint8_t* output, size_t length)
{
	uint8_t idx0;
	uint8_t idx1;
	size_t pos;

	static const uint8_t hashmap[] =
	{
		0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
		0x08U, 0x09U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
		0x00U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU, 0x00U,
		0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
	};

	if (hexstr != NULL && output != NULL)
	{
		qsc_memutils_clear(output, length);

		for (pos = 0U; pos < (length * 2U); pos += 2U)
		{
			idx0 = ((uint8_t)hexstr[pos] & 0x1FU) ^ 0x10U;
			idx1 = ((uint8_t)hexstr[pos + 1U] & 0x1FU) ^ 0x10U;
			output[pos / 2U] = (uint8_t)((uint8_t)(hashmap[idx0] << 4U) | hashmap[idx1]);
		}
	}
}

void aerntest_print_hex(const uint8_t* input, size_t inputlen, size_t linelen)
{
	size_t i;

	if (input != NULL && linelen != 0U)
	{
		while (inputlen >= linelen)
		{
			for (i = 0U; i < linelen; ++i)
			{
#if defined(_MSC_VER)
				printf_s("%02X", input[i]);
#else
				printf("%02X", input[i]);
#endif
			}

			input += linelen;
			inputlen -= linelen;
			aerntest_print_safe("\n");
		}

		for (i = 0U; i < inputlen; ++i)
		{
#if defined(_MSC_VER)
			printf_s("%02X", input[i]);
#else
			printf("%02X", input[i]);
#endif
		}
	}
}

void aerntest_print_safe(const char* input)
{
	if (input != NULL)
	{
		qsc_consoleutils_print_safe(input);
	}
}

void aerntest_print_line(const char* input)
{
	if (input != NULL)
	{
		qsc_consoleutils_print_line(input);
	}
}

void aerntest_print_ulong(uint64_t digit)
{
#if defined(_MSC_VER)
	printf_s("%llu", digit);
#else
	printf("%llu", (unsigned long long)digit);
#endif
}

void aerntest_print_double(double digit)
{
#if defined(_MSC_VER)
	printf_s("%.*lf", 3, digit);
#else
	printf("%.*lf", 3, digit);
#endif
}

bool aerntest_test_confirm(const char* message)
{
	char ans;
	bool res;

	res = false;
	aerntest_print_line(message);
	ans = aerntest_get_char();

	if (ans == 'y' || ans == 'Y')
	{
		res = true;
	}

	return res;
}

void aerntest_print_result(const char* name, bool passed)
{
	if (name != NULL)
	{
		aerntest_print_safe("[AERN-TEST] ");
		aerntest_print_safe(name);

		if (passed == true)
		{
			aerntest_print_line(" : PASS");
		}
		else
		{
			aerntest_print_line(" : FAIL");
		}
	}
}

bool aerntest_run_case(const aerntest_case* tcase)
{
	bool res;

	res = false;

	if (tcase != NULL && tcase->name != NULL && tcase->test != NULL)
	{
		res = tcase->test();
		aerntest_print_result(tcase->name, res);
	}

	return res;
}
