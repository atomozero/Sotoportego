/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 *
 * sotoportego_cli -- a tiny test client that proves the daemon's IPC + backend
 * seam works end to end. It launches the daemon if needed, subscribes for
 * updates, asks it to connect, prints every status/stats update it receives,
 * then asks it to disconnect and exits. No real VPN is involved this milestone.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Application.h>
#include <Message.h>
#include <MessageRunner.h>
#include <Messenger.h>
#include <Roster.h>
#include <OS.h>

#include "VPNProfile.h"
#include "VPNProtocol.h"
#include "VPNState.h"
#include "VPNStats.h"


// CLI-private messages (addressed to ourselves via timers).
static const uint32 kMsgDoDisconnect	= 'cDis';
static const uint32 kMsgTimeout			= 'cTmo';

// Linger briefly once connected so we observe a throughput tick before tearing
// down, then give the whole round-trip a hard deadline so the tool can never
// hang in CI.
static const bigtime_t kLingerWhenConnected = 1600000;	// 1.6s
static const bigtime_t kOverallTimeout = 20000000;		// 20s


class SotoportegoCLI : public BApplication {
public:
								SotoportegoCLI();
	virtual						~SotoportegoCLI();

	virtual	void				ReadyToRun();
	virtual	void				MessageReceived(BMessage* message);

			int					ExitCode() const { return fExitCode; }

private:
			status_t			_EnsureServer();
			void				_SendConnect();
			void				_PrintStats(const BMessage* message);

			BMessenger			fServer;
			BMessageRunner*		fLingerTimer;
			BMessageRunner*		fTimeoutTimer;
			bool				fConnectedSeen;
			bool				fDisconnectRequested;
			int					fExitCode;
};


SotoportegoCLI::SotoportegoCLI()
	:
	BApplication(kCLISignature),
	fLingerTimer(NULL),
	fTimeoutTimer(NULL),
	fConnectedSeen(false),
	fDisconnectRequested(false),
	fExitCode(0)
{
}


SotoportegoCLI::~SotoportegoCLI()
{
	delete fLingerTimer;
	delete fTimeoutTimer;
}


void
SotoportegoCLI::ReadyToRun()
{
	if (_EnsureServer() != B_OK) {
		fprintf(stderr, "[cli] could not reach the Sotoportego daemon\n");
		fExitCode = 1;
		PostMessage(B_QUIT_REQUESTED);
		return;
	}

	// Overall safety deadline.
	BMessage timeout(kMsgTimeout);
	fTimeoutTimer = new BMessageRunner(BMessenger(this), &timeout,
		kOverallTimeout, 1);

	_SendConnect();
}


status_t
SotoportegoCLI::_EnsureServer()
{
	// Launch the daemon if it is not already running. Both outcomes are fine.
	status_t launch = be_roster->Launch(kServerSignature);
	if (launch != B_OK && launch != B_ALREADY_RUNNING) {
		fprintf(stderr, "[cli] launch(%s) failed: %s\n", kServerSignature,
			strerror(launch));
		return launch;
	}

	// Registration can lag the launch slightly; retry until addressable.
	for (int attempt = 0; attempt < 30; attempt++) {
		fServer = BMessenger(kServerSignature);
		if (fServer.IsValid())
			return B_OK;
		snooze(100000);	// 0.1s
	}

	return B_ERROR;
}


void
SotoportegoCLI::_SendConnect()
{
	// A representative (but inert) profile. Real .ovpn parsing comes later.
	VPNProfile profile;
	profile.fBackendType = VPN_BACKEND_OPENVPN;
	profile.fName = "Demo Profile";
	profile.fServer = "vpn.example.com";
	profile.fPort = 1194;
	profile.fUsername = "demo";

	BMessage archive;
	profile.Archive(&archive);

	BMessage connect(kMsgConnect);
	connect.AddMessenger(kFieldClient, BMessenger(this));
	connect.AddMessage(kFieldProfile, &archive);

	printf("[cli] connecting to '%s' via daemon...\n", profile.fName.String());
	fServer.SendMessage(&connect);
}


void
SotoportegoCLI::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgStatusUpdate:
		{
			int32 state = VPN_STATE_DISCONNECTED;
			message->FindInt32(kFieldState, &state);

			const char* detail = NULL;
			if (message->FindString(kFieldDetail, &detail) != B_OK)
				detail = NULL;

			printf("[cli] state: %s%s%s\n", vpn_state_name((VPNState)state),
				detail != NULL ? " - " : "", detail != NULL ? detail : "");

			if (state == VPN_STATE_CONNECTED && !fDisconnectRequested) {
				fConnectedSeen = true;
				// Linger a moment, then ask the daemon to disconnect.
				BMessage tick(kMsgDoDisconnect);
				fLingerTimer = new BMessageRunner(BMessenger(this), &tick,
					kLingerWhenConnected, 1);
			} else if (state == VPN_STATE_DISCONNECTED && fConnectedSeen) {
				printf("[cli] round-trip complete; exiting\n");
				PostMessage(B_QUIT_REQUESTED);
			} else if (state == VPN_STATE_ERROR) {
				fExitCode = 1;
				PostMessage(B_QUIT_REQUESTED);
			}
			break;
		}

		case kMsgStatsUpdate:
			_PrintStats(message);
			break;

		case kMsgDoDisconnect:
		{
			fDisconnectRequested = true;
			printf("[cli] requesting disconnect\n");
			BMessage disconnect(kMsgDisconnect);
			disconnect.AddMessenger(kFieldClient, BMessenger(this));
			fServer.SendMessage(&disconnect);
			break;
		}

		case kMsgTimeout:
			fprintf(stderr, "[cli] timed out waiting for the round-trip\n");
			fExitCode = 1;
			PostMessage(B_QUIT_REQUESTED);
			break;

		default:
			BApplication::MessageReceived(message);
			break;
	}
}


void
SotoportegoCLI::_PrintStats(const BMessage* message)
{
	VPNStats stats;
	stats.Unarchive(*message);
	printf("[cli] stats: in=%lld bytes  out=%lld bytes\n",
		(long long)stats.fBytesIn, (long long)stats.fBytesOut);
}


int
main()
{
	SotoportegoCLI app;
	app.Run();

	return app.ExitCode();
}
