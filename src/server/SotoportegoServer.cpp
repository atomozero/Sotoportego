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
	fBackend(NULL),
	fProfiles()
{
	fProfiles.Load();
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
		case kMsgSaveProfile:
			_HandleSaveProfile(message);
			break;
		case kMsgDeleteProfile:
			_HandleDeleteProfile(message);
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

	// Forward any transient credentials to the backend before kicking the
	// connection off. These never get persisted; the backend wipes them in
	// Cleanup() when the session ends.
	const char* username = NULL;
	const char* password = NULL;
	if (message->FindString(kFieldUsername, &username) != B_OK)
		username = "";
	if (message->FindString(kFieldPassword, &password) != B_OK)
		password = "";
	if (username[0] != '\0' || password[0] != '\0')
		fBackend->SetCredentials(BString(username), BString(password));

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

	// Hand the new subscriber a snapshot of the profile list so it can
	// populate its UI without waiting for the first mutation.
	_SendProfileList(client);
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

	BString localIP = fBackend->LocalIP();
	if (localIP.Length() > 0)
		message->AddString(kFieldLocalIP, localIP);
	BString remoteIP = fBackend->RemoteIP();
	if (remoteIP.Length() > 0)
		message->AddString(kFieldRemoteIP, remoteIP);
}


void
SotoportegoServer::_HandleSaveProfile(BMessage* message)
{
	BMessage archive;
	if (message->FindMessage(kFieldProfile, &archive) != B_OK) {
		printf("[server] save-profile rejected: missing profile payload\n");
		return;
	}

	VPNProfile profile;
	profile.Unarchive(archive);

	status_t result = fProfiles.Save(profile);
	if (result != B_OK) {
		printf("[server] save-profile '%s' failed: %s\n",
			profile.fName.String(), strerror(result));
		return;
	}

	printf("[server] saved profile '%s' (%zu total)\n",
		profile.fName.String(), fProfiles.Count());
	_BroadcastProfileList();
}


void
SotoportegoServer::_HandleDeleteProfile(BMessage* message)
{
	const char* name = NULL;
	if (message->FindString(kFieldProfileName, &name) != B_OK || name == NULL) {
		printf("[server] delete-profile rejected: missing profile name\n");
		return;
	}

	status_t result = fProfiles.Delete(name);
	if (result != B_OK) {
		printf("[server] delete-profile '%s' failed: %s\n",
			name, strerror(result));
		return;
	}

	printf("[server] deleted profile '%s' (%zu total)\n",
		name, fProfiles.Count());
	_BroadcastProfileList();
}


void
SotoportegoServer::_SendProfileList(BMessenger to) const
{
	if (!to.IsValid())
		return;

	BMessage list(kMsgListProfiles);
	fProfiles.ArchiveAll(&list);
	to.SendMessage(&list);
}


void
SotoportegoServer::_BroadcastProfileList()
{
	BMessage list(kMsgListProfiles);
	fProfiles.ArchiveAll(&list);
	_Broadcast(&list);
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
