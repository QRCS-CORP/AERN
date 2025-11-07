#include "help.h"
#include "consoleutils.h"

static void help_print_line(const char* prompt, const char* line)
{
	AERN_ASSERT(prompt != NULL);
	AERN_ASSERT(line != NULL);

	qsc_consoleutils_print_safe(prompt);
	qsc_consoleutils_print_line(line);
}

void aern_help_print_context(const char* prompt, aern_command_actions command)
{
	AERN_ASSERT(prompt != NULL);

	if (prompt != NULL)
	{
		help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[(int)command]);
	}
}

void aern_help_print_mode(const char* prompt, aern_console_modes mode, aern_network_designations designation)
{
	AERN_ASSERT(prompt != NULL);

	if (prompt != NULL)
	{
		if (mode == aern_console_mode_config)
		{
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_config_address]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_config_certificate]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_config_clear_all]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_config_clear_config]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_config_clear_log]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_config_exit]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_config_help]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_config_log_host]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_config_name_domain]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_config_name_host]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_config_retries]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_config_server]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_config_timeout]);
		}
		else if (mode == aern_console_mode_enable)
		{
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_enable_clear_screen]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_enable_config]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_enable_exit]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_enable_help]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_enable_quit]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_enable_show_config]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_enable_show_log]);
		}
		else if (mode == aern_console_mode_user)
		{
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_user_enable]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_user_help]);
			help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_user_quit]);
		}
		else
		{
			if (designation == aern_network_designation_aps)
			{
				if (mode == aern_console_mode_certificate)
				{
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_exit]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_export]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_generate]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_help]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_import]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_print]);
				}
				else if (mode == aern_console_mode_server)
				{
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_backup]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_exit]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_help]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_list]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_register]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_resign]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_restore]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_service]);		
				}
			}
			if (designation == aern_network_designation_client)
			{
				if (mode == aern_console_mode_certificate)
				{
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_exit]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_export]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_generate]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_help]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_import]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_print]);
				}
				else if (mode == aern_console_mode_server)
				{
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_backup]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_connect]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_exit]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_help]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_list]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_query]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_register]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_resign]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_restore]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_service]);	
				}
				else if (mode == aern_console_mode_client_connected)
				{
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_connect]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_client_connect_help]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_client_connect_quit]);
				}
			}
			else if (designation == aern_network_designation_ads)
			{
				if (mode == aern_console_mode_certificate)
				{
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_exit]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_export]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_generate]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_help]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_import]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_print]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_adc_certificate_revoke]);
				}
				else if (mode == aern_console_mode_server)
				{
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_adc_server_announce]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_backup]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_adc_server_converge]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_exit]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_help]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_list]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_resign]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_restore]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_adc_server_revoke]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_service]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_adc_server_sproxy]);
				}
			}
			else if (designation == aern_network_designation_ars)
			{
				if (mode == aern_console_mode_certificate)
				{
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_exit]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_export]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_generate]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_help]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_import]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_print]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_certificate_sign]);
				}
				else if (mode == aern_console_mode_server)
				{
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_backup]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_exit]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_help]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_restore]);
					help_print_line(prompt, AERN_APPLICATION_HELP_STRINGS[aern_command_action_server_service]);	
				}
			}
			else
			{
				// TODO: IDG
			}
		}
	}
}
