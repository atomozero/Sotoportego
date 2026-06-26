/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "SotoportegoServer.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <Message.h>
#include <Notification.h>

#include "GeoLookup.h"
#include "OpenVPNBackend.h"
#include "VPNProfile.h"
#include "VPNProtocol.h"
#include "VPNStats.h"


// Internal 'what' for the geo-lookup result. Stays in this translation unit
// because no client should ever see it.
static const uint32 kMsgCountryResult = 'sCty';

// Identifier the notification server uses to update the same toast rather
// than stacking new ones for every transition.
static const char* const kNotificationGroup = "Sotoportego";
static const char* const kConnNotificationID = "soto-conn";


SotoportegoServer::SotoportegoServer()
	:
	BApplication(kServerSignature),
	fBackend(NULL),
	fProfiles(),
	fLastState(VPN_STATE_DISCONNECTED),
	fLastServerSummary()
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
			_HandleStatusForNotification(message);
			_Broadcast(message);
			break;
		case kMsgStatsUpdate:
			_Broadcast(message);
			break;

		// --- Internal: country lookup result ---------------------------
		case kMsgCountryResult:
			_HandleCountryResult(message);
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

	// Validate the .ovpn path before handing it to the backend. Anyone on
	// the local box can send us a Connect with an arbitrary `fConfigPath`,
	// and we hand that path to openvpn via --config. Without these checks
	// a malicious local app could ask the daemon to launch openvpn with,
	// say, "/etc/shadow" -- openvpn would echo parse errors that quote the
	// file contents into our log. So: absolute path, no .. segments, file
	// must exist and be readable as us.
	const BString& configPath = profile.fConfigPath;
	bool pathOk = configPath.Length() > 0 && configPath[0] == '/'
		&& configPath.FindFirst("..") < 0;
	if (pathOk && access(configPath.String(), R_OK) != 0)
		pathOk = false;
	if (!pathOk) {
		printf("[server] connect rejected: bad config path '%s'\n",
			configPath.String());
		BMessage reply(kMsgStatusUpdate);
		_FillStatus(&reply);
		reply.AddString(kFieldDetail,
			"profile config path is missing, not absolute, or unreadable");
		BMessenger client = _ClientFrom(message);
		if (client.IsValid())
			client.SendMessage(&reply);
		return;
	}

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


void
SotoportegoServer::_PostNotification(const char* title, const char* content,
	int32 type)
{
	BNotification notification((notification_type)type);
	notification.SetGroup(kNotificationGroup);
	notification.SetMessageID(kConnNotificationID);
	notification.SetTitle(title);
	notification.SetContent(content);
	notification.Send();
}


void
SotoportegoServer::_HandleStatusForNotification(BMessage* message)
{
	int32 stateValue = VPN_STATE_DISCONNECTED;
	message->FindInt32(kFieldState, &stateValue);
	VPNState newState = (VPNState)stateValue;
	VPNState previous = fLastState;
	fLastState = newState;
	if (newState == previous)
		return;

	switch (newState) {
		case VPN_STATE_CONNECTED:
		{
			// Build a one-line server summary up-front -- the geo-lookup
			// result needs the same line plus the country tag.
			const char* remote = NULL;
			if (message->FindString(kFieldRemoteIP, &remote) != B_OK)
				remote = NULL;
			fLastServerSummary = remote != NULL && *remote != '\0'
				? remote : "VPN";

			BString content("Connected to ");
			content << fLastServerSummary;
			_PostNotification("Sotoportego", content.String(),
				B_INFORMATION_NOTIFICATION);

			// Ask ip-api what country we appear to come from now that
			// traffic flows through the tunnel. The answer arrives later
			// as kMsgCountryResult.
			GeoLookup::BackgroundLookup(BMessenger(this), kMsgCountryResult);
			break;
		}

		case VPN_STATE_DISCONNECTED:
		{
			// Only surface a notification when we just came back from an
			// active session; ignore the noop "still disconnected" cases.
			if (previous != VPN_STATE_CONNECTED
					&& previous != VPN_STATE_RECONNECTING
					&& previous != VPN_STATE_AUTHENTICATING
					&& previous != VPN_STATE_CONNECTING) {
				break;
			}
			_PostNotification("Sotoportego", "VPN disconnected.",
				B_INFORMATION_NOTIFICATION);
			fLastServerSummary = "";
			break;
		}

		case VPN_STATE_ERROR:
		{
			const char* detail = NULL;
			if (message->FindString(kFieldDetail, &detail) != B_OK)
				detail = NULL;
			BString content("VPN error");
			if (detail != NULL && *detail != '\0') {
				content << ": ";
				content << detail;
			}
			content << ".";
			_PostNotification("Sotoportego", content.String(),
				B_ERROR_NOTIFICATION);
			fLastServerSummary = "";
			break;
		}

		default:
			// Intermediate states (Connecting, Authenticating,
			// Reconnecting) don't pop notifications -- the GUI's header
			// already shows them and we don't want to flood the user.
			break;
	}
}


void
SotoportegoServer::_HandleCountryResult(BMessage* message)
{
	// The lookup may have failed silently; in that case we keep the
	// original "Connected to ..." text rather than overwrite it with
	// something less informative.
	if (fLastState != VPN_STATE_CONNECTED)
		return;

	const char* country = NULL;
	if (message->FindString(GeoLookup::kFieldCountry, &country) != B_OK
			|| country == NULL || *country == '\0') {
		return;
	}

	// Server on the first line, country alone on the second -- the
	// context makes the label redundant and the country is the part
	// the eye lands on.
	BString content("Connected to ");
	if (fLastServerSummary.Length() > 0)
		content << fLastServerSummary;
	else
		content << "VPN";
	content << "\n";
	content << country;
	_PostNotification("Sotoportego", content.String(),
		B_INFORMATION_NOTIFICATION);

	// Also push a status update so subscribed clients (the GUI) can
	// surface the country in their own UI. Reuses _FillStatus so the
	// payload looks like any other status broadcast plus the new
	// kFieldCountry field.
	BMessage update(kMsgStatusUpdate);
	_FillStatus(&update);
	update.AddString(kFieldCountry, country);
	_Broadcast(&update);
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
