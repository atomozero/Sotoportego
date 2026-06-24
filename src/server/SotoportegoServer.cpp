/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "SotoportegoServer.h"

#include <stdio.h>
#include <string.h>

#include <Message.h>

#include "OpenVPNBackend.h"
#include "VPNProfile.h"
#include "VPNProtocol.h"
#include "VPNStats.h"


SotoportegoServer::SotoportegoServer()
	:
	BApplication(kServerSignature),
	fBackend(NULL)
{
}


SotoportegoServer::~SotoportegoServer()
{
	// Once AddHandler() succeeds, the looper owns fBackend and deletes it as
	// part of its own teardown, so we must not delete it here.
}


void
SotoportegoServer::ReadyToRun()
{
	// Create the single backend instance and attach it to our looper so it can
	// receive its own timer ticks. We run on the looper thread here, so the
	// looper is already locked.
	// TODO(milestone-2): choose the backend from the connecting profile's
	// VPNBackendType instead of hard-coding OpenVPN.
	fBackend = new OpenVPNBackend();
	AddHandler(fBackend);
	fBackend->SetObserver(BMessenger(this));

	printf("[server] Sotoportego daemon ready (%s)\n", kServerSignature);
}


void
SotoportegoServer::MessageReceived(BMessage* message)
{
	switch (message->what) {
		// --- Requests from clients -------------------------------------
		case kMsgConnect:
			_HandleConnect(message);
			break;
		case kMsgDisconnect:
			_HandleDisconnect(message);
			break;
		case kMsgSubscribe:
			_HandleSubscribe(message);
			break;
		case kMsgUnsubscribe:
			_HandleUnsubscribe(message);
			break;
		case kMsgGetStatus:
			_HandleGetStatus(message);
			break;

		// --- Events from the backend (we are its observer) -------------
		// The backend addresses these to us; we fan them out to clients.
		case kMsgStatusUpdate:
		case kMsgStatsUpdate:
			_Broadcast(message);
			break;

		default:
			BApplication::MessageReceived(message);
			break;
	}
}


void
SotoportegoServer::_HandleConnect(BMessage* message)
{
	if (fBackend == NULL)
		return;

	VPNProfile profile;
	BMessage archive;
	if (message->FindMessage(kFieldProfile, &archive) == B_OK)
		profile.Unarchive(archive);

	// A connect implies the sender wants updates.
	_HandleSubscribe(message);

	status_t result = fBackend->Connect(profile);
	if (result != B_OK) {
		printf("[server] connect rejected: %s\n", strerror(result));
		BMessage reply(kMsgStatusUpdate);
		_FillStatus(&reply);
		reply.AddString(kFieldDetail, strerror(result));
		BMessenger client = _ClientFrom(message);
		if (client.IsValid())
			client.SendMessage(&reply);
	}
}


void
SotoportegoServer::_HandleDisconnect(BMessage* /*message*/)
{
	if (fBackend != NULL)
		fBackend->Disconnect();
}


void
SotoportegoServer::_HandleSubscribe(BMessage* message)
{
	BMessenger client = _ClientFrom(message);
	if (!client.IsValid())
		return;

	for (size_t i = 0; i < fClients.size(); i++) {
		if (fClients[i] == client)
			return;	// already subscribed; idempotent
	}

	fClients.push_back(client);
	printf("[server] client subscribed (%zu total)\n", fClients.size());
}


void
SotoportegoServer::_HandleUnsubscribe(BMessage* message)
{
	BMessenger client = _ClientFrom(message);

	for (size_t i = 0; i < fClients.size(); i++) {
		if (fClients[i] == client) {
			fClients.erase(fClients.begin() + i);
			printf("[server] client unsubscribed (%zu total)\n",
				fClients.size());
			return;
		}
	}
}


void
SotoportegoServer::_HandleGetStatus(BMessage* message)
{
	BMessenger client = _ClientFrom(message);
	if (!client.IsValid())
		return;

	BMessage reply(kMsgStatusUpdate);
	_FillStatus(&reply);
	client.SendMessage(&reply);
}


void
SotoportegoServer::_Broadcast(BMessage* message)
{
	// Iterate over a snapshot index and prune clients whose looper has gone
	// away (SendMessage returns an error for a dead target).
	for (size_t i = 0; i < fClients.size();) {
		if (fClients[i].SendMessage(message) == B_OK) {
			i++;
		} else {
			fClients.erase(fClients.begin() + i);
			printf("[server] dropped dead client (%zu total)\n",
				fClients.size());
		}
	}
}


void
SotoportegoServer::_FillStatus(BMessage* message)
{
	if (fBackend == NULL) {
		message->AddInt32(kFieldState, (int32)VPN_STATE_DISCONNECTED);
		return;
	}

	message->AddInt32(kFieldState, (int32)fBackend->State());
	message->AddString(kFieldBackend, fBackend->BackendName());
	fBackend->Stats().Archive(message);
}


BMessenger
SotoportegoServer::_ClientFrom(BMessage* message) const
{
	// Prefer an explicit client messenger; fall back to the message's reply
	// address so a bare request still gets answered.
	BMessenger client;
	if (message->FindMessenger(kFieldClient, &client) == B_OK
			&& client.IsValid()) {
		return client;
	}

	return message->ReturnAddress();
}
