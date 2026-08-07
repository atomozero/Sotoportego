/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include <stdio.h>

#include "SotoportegoServer.h"


int
main()
{
	// Unbuffer stdout so the daemon's diagnostic logs (state transitions,
	// [tailscale]/[OpenVPN]/[WireGuard]/[tun]/[route] lines) appear -- and, on a
	// hard crash, the last line before it is not lost -- even when the output is
	// a pipe or a file, not a terminal. (Line-buffering with a NULL/zero buffer
	// falls back to full buffering on Haiku when the target isn't a tty, which
	// silently swallowed the logs.) The daemon's log volume is low, so the extra
	// write syscalls per line are irrelevant.
	setvbuf(stdout, NULL, _IONBF, 0);

	SotoportegoServer app;
	app.Run();

	return 0;
}
