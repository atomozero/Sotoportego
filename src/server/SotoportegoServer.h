/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef SOTOPORTEGO_SERVER_H
#define SOTOPORTEGO_SERVER_H


#include <vector>

#include <Application.h>
#include <Messenger.h>

#include "VPNState.h"

class VPNBackend;


// The Sotoportego daemon.
//
// This process owns the VPN lifecycle. Front-ends (GUI, Deskbar replicant,
// CLI) are separate processes that drive it over BMessage; the daemon never
// trusts a client with the connection state directly. For Milestone 1 it runs
// as the normal user and holds a single backend instance, but the
// process boundary is real so privilege separation can be added later without
// reshaping the architecture.
//
// As a BApplication it is also a BLooper, which hosts the backend handler and
// dispatches both client requests and backend events on one thread.
class SotoportegoServer : public BApplication {
public:
								SotoportegoServer();
	virtual						~SotoportegoServer();

	virtual	void				ReadyToRun();
	virtual	void				MessageReceived(BMessage* message);

private:
			void				_HandleConnect(BMessage* message);
			void				_HandleDisconnect(BMessage* message);
			void				_HandleSubscribe(BMessage* message);
			void				_HandleUnsubscribe(BMessage* message);
			void				_HandleGetStatus(BMessage* message);

	// Re-broadcast a backend event (state or stats) to every subscribed
	// client, pruning any that have gone away.
			void				_Broadcast(BMessage* message);

	// Build a fresh status snapshot from the backend.
			void				_FillStatus(BMessage* message);

			BMessenger			_ClientFrom(BMessage* message) const;

			VPNBackend*				fBackend;
			std::vector<BMessenger>	fClients;
};


#endif	// SOTOPORTEGO_SERVER_H
