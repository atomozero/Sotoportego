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
