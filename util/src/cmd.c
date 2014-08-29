#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <malloc.h>

#include "cmd.h"
#include "map.h"

static Map* variables = NULL;
char cmd_result[CMD_RESULT_SIZE];

void cmd_init(void) {
	variables = map_create(16, map_string_hash, map_string_equals, NULL);
	map_put(variables, strdup("$?"), strdup("(nil)"));
	map_put(variables, strdup("$nil"), strdup("(nil)"));
}

int cmd_help(int argc, char** argv) {
        int command_len = 0;
        for(int i = 0; commands[i].name != NULL; i++) {
                int len = strlen(commands[i].name);
                command_len = len > command_len ? len : command_len;
        }

        for(int i = 0; commands[i].name != NULL; i++) {
                printf("%s", commands[i].name);
                int len = strlen(commands[i].name);
                len = command_len - len + 2;
                for(int j = 0; j < len; j++)
                       putchar(' ');
		if(commands[i].args != NULL)
                	printf("%s  %s\n", commands[i].desc, commands[i].args);
		else
			printf("%s\n", commands[i].desc);
        }
	cmd_result[0] = '\0';

        return 0;
}

static int cmd_parse_line(char* line, char** argv) {
	int argc = 0;
	bool is_start = true;
	char quotation = 0;
	int str_len =  strlen(line);
	char* start = line;
	for(int i = 0;i < (str_len + 1); i++) {
		if(quotation != 0) {
			if(line[i] == quotation) {
				quotation = 0;
				line[i] = '\0';
				line[i + 1] = '\0';
				i++;
				is_start = true;
			}
		} else {
			switch(line[i]) {
				case '\'':
				case '"':
					quotation = line[i];
					line[i] = '\0';
					i++;
					argv[argc++] = start;
					break;
				case ' ':
				case '\0':
					if(is_start == false) {
						line[i] = '\0';
						argv[argc++] = start;
						is_start = true;
					}
					break;
				default:
					if(is_start == true) {
						start = &line[i];
						is_start = false;
					}
					break;
			}
		}
	}

	return argc;
}

static char* cmd_parse_var(int* argc, char** argv) {
	char* variable = NULL;
	if(*argc >= 2) {
		if((argv[0][0] == '$') && (argv[1][0] == '=')) {
			variable = strdup(argv[0]);
			memmove(&argv[0], &argv[2], sizeof(char*) * (*argc - 2));
			*argc -= 2;
		}
	}

	return variable;	
}

static void cmd_parse_arg(int argc, char** argv) {
	for(int i = 0; i < argc; i++) {
		if(argv[i][0] == '$') {
			if(!map_contains(variables, argv[i])) {
				argv[i] = map_get(variables, "$nil");
			} else {
				argv[i] = map_get(variables, argv[i]);
			}
		}
	}
}

static Command* cmd_get(int argc, char** argv) {
        for(int i = 0; commands[i].name != NULL; i++) {
                if(strcmp(argv[0], commands[i].name) == 0) {
                        return &commands[i];
                }
        }
        if(argc > 0)
                printf("%s : command not found\n", argv[0]);

        return NULL;
}

static void cmd_update_var(int exit_status, char* variable) {
	char buf[16];
	sprintf(buf, "%d", exit_status);
	
	free(map_get(variables, "$?"));
	map_update(variables, "$?", strdup(buf));

	if(exit_status == 0) {
		if(variable) {
			if(map_contains(variables, variable)) {
				free(map_get(variables, variable));
				if(strlen(cmd_result) > 0)
					map_update(variables, variable, strdup(cmd_result));
				else
					map_update(variables, variable, strdup("(nil)"));
			
			} else {
				if(strlen(cmd_result) > 0)
					map_put(variables, strdup(variable), strdup(cmd_result));
				else
					map_put(variables, strdup(variable), strdup("(nil)"));
			}
		}
		if(strlen(cmd_result) > 0) {
			printf("%s\n", cmd_result);
		}
	}
}

int cmd_exec(char* line) {
	int argc;
	char* argv[CMD_MAX_ARGC];
	
	argc = cmd_parse_line(line, argv);
	if(argv[0][0] == '#')
		return 0;

	char* variable = cmd_parse_var(&argc, argv);
	cmd_parse_arg(argc, argv);
	Command* cmd = cmd_get(argc, argv);
	int exit_status = 0;
	if(cmd != NULL) {
		exit_status = cmd->func(argc, argv);
		cmd_update_var(exit_status, variable);
	}
	free(variable);

	return exit_status;
}
