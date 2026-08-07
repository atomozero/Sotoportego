/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSBackoff.h"


namespace ts {

ReconnectBackoff::ReconnectBackoff(bigtime_t minDelay, bigtime_t maxDelay,
	bigtime_t healthyThreshold)
	:
	fMin(minDelay > 0 ? minDelay : 1),
	fMax(maxDelay >= minDelay ? maxDelay : minDelay),
	fHealthy(healthyThreshold),
	fCurrent(minDelay > 0 ? minDelay : 1)
{
}


bigtime_t
ReconnectBackoff::NextDelay(bool established, bigtime_t lasted)
{
	// A session that came up and ran long enough was a transient drop -- retry
	// promptly and forget any accumulated backoff.
	if (established && lasted >= fHealthy) {
		fCurrent = fMin;
		return fCurrent;
	}

	// Otherwise wait the current delay, then double it for next time (capped).
	bigtime_t delay = fCurrent;
	bigtime_t next = fCurrent * 2;
	if (next > fMax)
		next = fMax;
	fCurrent = next;
	return delay;
}


void
ReconnectBackoff::Reset()
{
	fCurrent = fMin;
}

}	// namespace ts
