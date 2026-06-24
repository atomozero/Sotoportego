/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "VPNStats.h"

#include <Message.h>

#include "VPNProtocol.h"


VPNStats::VPNStats()
{
	Reset();
}


void
VPNStats::Reset()
{
	fBytesIn = 0;
	fBytesOut = 0;
	fConnectedSince = 0;
}


status_t
VPNStats::Archive(BMessage* into) const
{
	if (into == NULL)
		return B_BAD_VALUE;

	status_t result = into->AddInt64(kFieldBytesIn, fBytesIn);
	if (result == B_OK)
		result = into->AddInt64(kFieldBytesOut, fBytesOut);
	if (result == B_OK)
		result = into->AddInt64(kFieldConnectedSince, (int64)fConnectedSince);

	return result;
}


status_t
VPNStats::Unarchive(const BMessage& from)
{
	// Missing fields are tolerated and left at their defaults so that partial
	// messages (e.g. a state-only update) still parse cleanly.
	int64 value;
	if (from.FindInt64(kFieldBytesIn, &value) == B_OK)
		fBytesIn = value;
	if (from.FindInt64(kFieldBytesOut, &value) == B_OK)
		fBytesOut = value;
	if (from.FindInt64(kFieldConnectedSince, &value) == B_OK)
		fConnectedSince = (time_t)value;

	return B_OK;
}
