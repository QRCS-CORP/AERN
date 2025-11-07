#include "menu.h"
#include "logger.h"
#include "resources.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "stringutils.h"

const char* aern_menu_get_prompt(aern_console_modes mode)
{
	return AERN_APPLICATION_MODE_STRINGS[(size_t)mode];
}

void aern_menu_print_error(aern_protocol_errors error, aern_console_modes mode, const char* host)
{
	AERN_ASSERT(host != NULL);

	const char* msg;

	if (host != NULL)
	{
		msg = aern_protocol_error_to_string(error);

		if (msg != NULL)
		{
			aern_menu_print_prompt(mode, host);
			qsc_consoleutils_print_line(msg);
		}
	}
}

void aern_menu_print_message(const char* message, aern_console_modes mode, const char* host)
{
	AERN_ASSERT(message != NULL);
	AERN_ASSERT(host != NULL);

	if (message != NULL && host != NULL)
	{
		aern_menu_print_prompt(mode, host);

		if (qsc_stringutils_string_size(message) > 0U)
		{
			qsc_consoleutils_print_line(message);
		}
	}
}

bool aern_menu_print_message_confirm(const char* message, aern_console_modes mode, const char* host)
{
	AERN_ASSERT(message != NULL);
	AERN_ASSERT(host != NULL);

	char ans;
	bool res;

	res = false;

	if (message != NULL && host != NULL)
	{
		aern_menu_print_message(message, mode, host);
		aern_menu_print_prompt(mode, host);
		ans = qsc_consoleutils_get_char();

		if (ans == 'y' || ans == 'Y')
		{
			res = true;
		}
	}

	return res;
}

void aern_menu_print_prompt_text(const char* message, aern_console_modes mode, const char* host)
{
	AERN_ASSERT(message != NULL);
	AERN_ASSERT(host != NULL);

	if (message != NULL && host != NULL)
	{
		aern_menu_print_prompt(mode, host);

		if (qsc_stringutils_string_size(message) > 0U)
		{
			qsc_consoleutils_print_safe(message);
		}
	}
}

void aern_menu_print_text(const char* message)
{
	AERN_ASSERT(message != NULL);

	if (message != NULL)
	{
		if (qsc_stringutils_string_size(message) > 0U)
		{
			qsc_consoleutils_print_safe(message);
		}
	}
}

void aern_menu_print_text_line(const char* message)
{
	AERN_ASSERT(message != NULL);

	if (message != NULL)
	{
		if (qsc_stringutils_string_size(message) > 0U)
		{
			qsc_consoleutils_print_line(message);
		}
	}
}

bool aern_menu_print_predefined_message_confirm(aern_application_messages msgnum, aern_console_modes mode, const char* host)
{
	AERN_ASSERT(host != NULL);

	char ans[8U] = { 0 };
	bool res;

	res = false;

	if (host != NULL)
	{
		aern_menu_print_predefined_message(msgnum, mode, host);
		aern_menu_print_prompt(mode, host);

		if (qsc_consoleutils_get_line(ans, sizeof(ans)) > 0U)
		{
			if (ans[0U] == 'y' || ans[0U] == 'Y')
			{
				res = true;
			}
		}
	}

	return res;
}

void aern_menu_print_predefined_message(aern_application_messages msgnum, aern_console_modes mode, const char* host)
{
	AERN_ASSERT(host != NULL);

	if (host != NULL)
	{
		aern_menu_print_prompt(mode, host);
		qsc_consoleutils_print_line(AERN_APPLICATION_MESSAGE_STRINGS[(size_t)msgnum]);
	}
}

void aern_menu_print_predefined_text(aern_application_messages msgnum, aern_console_modes mode, const char* host)
{
	AERN_ASSERT(host != NULL);

	if (host != NULL)
	{
		aern_menu_print_prompt(mode, host);
		qsc_consoleutils_print_safe(AERN_APPLICATION_MESSAGE_STRINGS[(size_t)msgnum]);
	}
}

void aern_menu_print_prompt(aern_console_modes mode, const char* host)
{
	AERN_ASSERT(host != NULL);

	char pmt[AERN_STORAGE_PROMPT_MAX + 1U] = { 0 };

	if (host != NULL)
	{
		qsc_stringutils_concat_and_copy(pmt, sizeof(pmt), host, AERN_APPLICATION_MODE_STRINGS[(size_t)mode]);
		qsc_consoleutils_print_safe(pmt);
	}
}

void aern_menu_print_prompt_empty(void)
{
	qsc_consoleutils_print_safe("aern> ");
}
