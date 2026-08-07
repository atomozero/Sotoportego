/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "PeerPath.h"


namespace ts {

PeerPath::PeerPath()
	:
	fMode(PATH_NONE),
	fEndpoint(""),
	fLastDirectActivity(0)
{
}


void
PeerPath::UseDerp()
{
	// Only take the DERP path if we don't already have a working direct one;
	// a live direct path should never be downgraded just because the netmap
	// re-advertised the peer.
	if (fMode == PATH_NONE)
		fMode = PATH_DERP;
}


void
PeerPath::UpgradeToDirect(const char* endpoint, bigtime_t now)
{
	fMode = PATH_DIRECT;
	fEndpoint = endpoint != NULL ? endpoint : "";
	fLastDirectActivity = now;
}


void
PeerPath::NoteDirectActivity(bigtime_t now)
{
	if (fMode == PATH_DIRECT)
		fLastDirectActivity = now;
}


PathMode
PeerPath::Evaluate(bigtime_t now, bigtime_t staleAfterUs)
{
	if (fMode == PATH_DIRECT && now - fLastDirectActivity > staleAfterUs) {
		// The direct path has gone quiet: fall back to DERP (keep the endpoint
		// so a later pong can re-upgrade cheaply).
		fMode = PATH_DERP;
	}
	return fMode;
}

}	// namespace ts
