/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TunDevice.h"

#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>


extern "C" char** environ;


bool
TunDevice::RunIfconfig(const char* const argv[], bool quiet)
{
	pid_t pid = -1;
	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_t* actionsPtr = NULL;
	bool actionsInited = false;
	if (quiet && posix_spawn_file_actions_init(&actions) == 0) {
		actionsInited = true;
		if (posix_spawn_file_actions_addopen(&actions, STDERR_FILENO,
				"/dev/null", O_WRONLY, 0) == 0) {
			actionsPtr = &actions;
		}
	}

	int rc = posix_spawnp(&pid, "ifconfig", actionsPtr, NULL,
		(char* const*)argv, environ);
	// Destroy whenever init succeeded, not just when we ended up passing the
	// actions to spawn: if addopen failed, actionsPtr stayed NULL but the
	// initialised object still had to be freed.
	if (actionsInited)
		posix_spawn_file_actions_destroy(&actions);

	if (rc != 0) {
		fprintf(stderr, "[tun] spawn(ifconfig) failed: %s\n", strerror(rc));
		return false;
	}
	int status = 0;
	if (waitpid(pid, &status, 0) != pid)
		return false;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}


bool
TunDevice::ProbeFreeSlot(BString& outInterface, BString& outNode)
{
	outInterface = "";
	outNode = "";

	for (int slot = 0; slot < 8; slot++) {
		BString interfaceName;
		interfaceName << "tun/" << slot;

		// Quiet mode for the probe: an "Invalid Argument" on --delete just
		// means the slot wasn't in the interface list, and a "General system
		// error" on up means the kernel left this slot in a stuck state
		// (typically after a kill -9 of the previous session) and only a
		// reboot will free it. Both are expected outcomes of the probe;
		// logging them as ifconfig errors makes a clean startup look broken.
		const char* const ifconfigDelete[] = {
			"ifconfig", "--delete", interfaceName.String(), NULL
		};
		RunIfconfig(ifconfigDelete, /*quiet=*/true);

		const char* const ifconfigUp[] = {
			"ifconfig", interfaceName.String(), "up", NULL
		};
		if (RunIfconfig(ifconfigUp, /*quiet=*/true)) {
			outInterface = interfaceName;
			outNode << "/dev/tun/" << slot;
			printf("[tun] using %s (%s)\n",
				outInterface.String(), outNode.String());
			return true;
		}
		printf("[tun] %s is stuck (kernel-side); trying next slot\n",
			interfaceName.String());
	}

	return false;
}


bool
TunDevice::RunRoute(const char* const argv[])
{
	// Printable form for the log so the user can correlate with a hand-run
	// command.
	BString line("[route]");
	for (int i = 1; argv[i] != NULL; i++) {
		line << " ";
		line << argv[i];
	}

	pid_t pid = -1;
	int rc = posix_spawnp(&pid, "route", NULL, NULL,
		(char* const*)argv, environ);
	if (rc != 0) {
		fprintf(stderr, "%s [spawn failed: %s]\n", line.String(), strerror(rc));
		return false;
	}
	int status = 0;
	if (waitpid(pid, &status, 0) != pid) {
		fprintf(stderr, "%s [waitpid failed]\n", line.String());
		return false;
	}
	bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	if (ok)
		printf("%s\n", line.String());
	else {
		fprintf(stderr, "%s [exit %d]\n", line.String(),
			WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	}
	return ok;
}


static bool
looks_like_ipv4(const BString& s)
{
	int dots = 0;
	for (int32 i = 0; i < s.Length(); i++) {
		char c = s.ByteAt(i);
		if (c == '.')
			dots++;
		else if (c < '0' || c > '9')
			return false;
	}
	return dots == 3;
}


bool
TunDevice::DefaultGateway(BString& gateway, BString& iface)
{
	// Parse `route`'s table. Haiku prints the default route as destination
	// 0.0.0.0 with netmask 0.0.0.0 and the interface as the last column; the
	// next-hop is the first dotted-quad after the netmask that isn't 0.0.0.0.
	FILE* fp = popen("route", "r");
	if (fp == NULL)
		return false;

	bool found = false;
	char line[512];
	while (!found && fgets(line, sizeof(line), fp) != NULL) {
		BString tokens[16];
		int count = 0;
		char* save = NULL;
		for (char* tok = strtok_r(line, " \t\r\n", &save);
				tok != NULL && count < 16;
				tok = strtok_r(NULL, " \t\r\n", &save)) {
			tokens[count++] = tok;
		}
		if (count < 3 || tokens[0] != "0.0.0.0" || tokens[1] != "0.0.0.0")
			continue;

		for (int i = 2; i < count - 1; i++) {
			if (looks_like_ipv4(tokens[i]) && tokens[i] != "0.0.0.0") {
				gateway = tokens[i];
				iface = tokens[count - 1];
				found = true;
				break;
			}
		}
	}
	pclose(fp);
	return found;
}
