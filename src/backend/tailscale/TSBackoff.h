/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_BACKOFF_H
#define TS_BACKOFF_H


#include <SupportDefs.h>


// Reconnect backoff policy for the control map long-poll (and reusable for the
// DERP relay). The map stream is expected to stay open for a long time; when it
// drops we want to re-establish it -- fast if the drop looks transient, but with
// a growing delay if we're failing to connect at all, so a dead coordination
// server isn't hammered.
//
// The policy is deliberately a tiny, side-effect-free state machine so it can be
// unit-tested without any network: feed it the outcome of each attempt and it
// returns the delay to wait before the next one.
namespace ts {

class ReconnectBackoff {
public:
	// minDelay/maxDelay bound the wait; healthyThreshold is how long a session
	// must have stayed up to count as "healthy" (a transient drop) rather than a
	// flap -- a healthy drop resets the delay to minDelay.
							ReconnectBackoff(bigtime_t minDelay,
								bigtime_t maxDelay, bigtime_t healthyThreshold);

	// Report the just-ended attempt and get the microseconds to wait before the
	// next one. `established` is whether the session ever came up (got its first
	// netmap); `lasted` is how long it ran. A healthy drop resets to minDelay;
	// anything else grows geometrically, capped at maxDelay.
			bigtime_t		NextDelay(bool established, bigtime_t lasted);

	// The delay the next NextDelay() would grow from (for inspection/tests).
			bigtime_t		Current() const { return fCurrent; }
			void			Reset();

private:
			bigtime_t		fMin;
			bigtime_t		fMax;
			bigtime_t		fHealthy;
			bigtime_t		fCurrent;
};

}	// namespace ts


#endif	// TS_BACKOFF_H
