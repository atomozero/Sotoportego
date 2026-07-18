/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include <stdio.h>

#include "SotoportegoServer.h"


int
main()
{
	// Line-buffer stdout so the daemon's diagnostic logs (state transitions,
	// [OpenVPN]/[WireGuard]/[tun]/[route] lines) appear promptly even when the
	// output is a pipe, not a terminal -- e.g. when launched by the GUI or
	// captured to a file for debugging.
	setvbuf(stdout, NULL, _IOLBF, 0);

	SotoportegoServer app;
	app.Run();

	return 0;
}
