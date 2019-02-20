#ifndef CMDLINE_ARGS_H
#define CMDLINE_ARGS_H

#include "argparse.h"

static const char *const usage[] = {
	"tcploadgen [options]",
	NULL,
};

typedef struct cmdline_args_s {
	int clients;
	int rate;
	int prefix;
	int time;
	int msglen;
	char *message;
	char *server;
	char host[255];
	int port;
} cmdline_args_t;

cmdline_args_t cmdline_args = {
	.clients = 0,
	.rate = 0,
	.prefix = 0,
	.time = 0,
	.msglen = 0,
	.message = NULL,
	.server = NULL,
	.host = { 0 },
	.port = 0,
};

int parse_tcploadgen_args(int argc, const char **argv)
{
	struct argparse_option options[] = {
		OPT_HELP(),
		OPT_GROUP("Required arguments"),
		OPT_INTEGER('c', "clients", &cmdline_args.clients, "number of concurrent clients"),
		OPT_INTEGER('r', "rate", &cmdline_args.rate, "send rate (messages per second)"),
		OPT_INTEGER('t', "time", &cmdline_args.time, "time for clients to transmit (in second)"),
		OPT_STRING('m', "message", &cmdline_args.message, "message to send"),
		OPT_STRING('s', "server", &cmdline_args.server, "ip:port of tcp server"),
		OPT_GROUP("Optional arguments"),
		OPT_INTEGER('p', "prefix", &cmdline_args.prefix, "add an int length prefix to the message using this bitlen (8, 16, 32, or 64)"),
		OPT_END(),
	};

	struct argparse argparse;
	argparse_init(&argparse, options, usage, 0);
	argparse_describe(&argparse, "\ntcploadgen generates load on your tcp server for testing purposes", "\nExample usage -- connect to localhost on port 7777 with 1 client, sending 1 message per second, with the message prefixed using a 32bit int length\ntcploadgen -c 1 -r 1 -m \"Hello world\" -s 127.0.0.1:7777 -p 32\n");
	argc = argparse_parse(&argparse, argc, argv);
	if (cmdline_args.clients <= 0) {
		cmdline_args.clients = 1;
	}

	if (cmdline_args.rate <= 0) {
		cmdline_args.rate = 1;
	}

	if (cmdline_args.time <= 0) {
		cmdline_args.time = 10;
	}

	if (cmdline_args.message == NULL) {
		printf("Invalid or missing message\n");
		argparse_usage(&argparse);
		return -1;
	}

	cmdline_args.msglen = (int)strlen(cmdline_args.message);
	if (cmdline_args.msglen <= 0) {
		printf("Invalid or missing message\n");
		argparse_usage(&argparse);
		return -1;
	}

	if (cmdline_args.server == NULL) {
		printf("Invalid or missing server\n");
		argparse_usage(&argparse);
		return -1;
	}

	struct aws_byte_cursor bc_server = aws_byte_cursor_from_c_str(cmdline_args.server);
	struct aws_array_list bc_list;
	struct aws_byte_cursor bc_array[2];
	aws_array_list_init_static(&bc_list, &bc_array, 2, sizeof(struct aws_byte_cursor));
	if (aws_byte_cursor_split_on_char(&bc_server, ':', &bc_list) != AWS_OP_SUCCESS) {
		printf("Invalid server (must be IP:Port format): %s\n", cmdline_args.server);
		argparse_usage(&argparse);
		return -1;
	}

	if (bc_array[0].len > 16 || bc_array[0].len <= 0 || bc_array[1].len > 5 || bc_array[0].len <= 0) {
		printf("Invalid server (must be IP:Port format): %s\n", cmdline_args.server);
		argparse_usage(&argparse);
		return -1;
	}

	char shost[32] = { 0 };
	char sport[32] = { 0 };
	memcpy(shost, bc_array[0].ptr, bc_array[0].len);
	memcpy(sport, bc_array[1].ptr, bc_array[1].len);
	int port = atoi(sport);

	if (port <= 0 || port > 65535) {
		printf("Invalid port: %s\n", cmdline_args.server);
		argparse_usage(&argparse);
		return -1;
	}

	memcpy(cmdline_args.host, shost, 32);
	cmdline_args.port = port;

	if (cmdline_args.prefix != 0) {
		if ((cmdline_args.prefix % 8) != 0 || cmdline_args.prefix > 64 || cmdline_args.prefix < 0) {
			printf("Invalid prefix length, must the bit length of an int: 8, 16, 32, or 64\n");
			argparse_usage(&argparse);
			return -1;
		}
	}

	return 0;
}

#endif