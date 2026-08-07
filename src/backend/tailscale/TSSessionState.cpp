/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSSessionState.h"


namespace ts {

SessionState::SessionState()
	:
	fSelfIP("")
{
}


bool
SessionState::ApplyMapResponse(const char* json, size_t len, int* outAdded,
	int* outRemoved, int* outUpdated)
{
	if (!fNetmap.Parse(json, len))
		return false;

	// Reconcile the WireGuard peer set and refresh MagicDNS + our own address
	// from the freshly parsed netmap.
	fPeers.Update(fNetmap, outAdded, outRemoved, outUpdated);
	fDns.LoadFromNetmap(fNetmap);
	fSelfIP = fNetmap.SelfIPv4();
	return true;
}

}	// namespace ts
