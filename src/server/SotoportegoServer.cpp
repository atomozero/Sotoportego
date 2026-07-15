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

#include <fcntl.h>
#include <sys/stat.h>

#include <Directory.h>
#include <File.h>
#include <FindDirectory.h>
#include <Path.h>

#include "GeoLookup.h"
#include "OpenVPNBackend.h"
#include "VPNGateFetcher.h"
#include "VPNProfile.h"
#include "VPNProtocol.h"
#include "VPNStats.h"


// Internal 'what' for the geo-lookup result. Stays in this translation unit
// because no client should ever see it.
static const uint32 kMsgCountryResult	= 'sCty';
// Same idea but for the "home" geo lookup, fired off when no VPN is up so
// the map knows where to plant the "you are here" pin.
static const uint32 kMsgHomeGeoResult	= 'sHom';

// Internal 'what' fired by VPNGateFetcher once the catalogue is in (or once
// the fetch has failed). Carries the same payload as kMsgVPNGateList; we
// rewrap it before broadcasting.
static const uint32 kMsgVPNGateFetched = 'sVGr';

// How long a successful catalogue stays warm before we ask vpngate again.
// Public-server churn is on the order of hours; an interactive user is more
// likely to want a snappier "Refresh" than a perpetually up-to-the-minute list.
static const bigtime_t kCatalogueTTL	= 10 * 60 * 1000000LL;	// 10 minutes

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
	fLastServerSummary(),
	fConnectedHost(),
	fHomeCountry(),
	fHomeIP(),
	fHomeLat(0.0f),
	fHomeLon(0.0f),
	fHomeLookupInFlight(false),
	fCatalogueCache(),
	fCatalogueFetchedAt(0),
	fCatalogueFetchInFlight(false),
	fCataloguePending()
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

	// If the previous run crashed mid-session it left the default route
	// pointing at a dead tun device, which means the user has no internet
	// right now. Roll the routes back to whatever the session file recorded
	// so they're online again before they have to look up what we did.
	fBackend->RecoverIfCrashed();

	// Kick off the first "where are we without a VPN?" lookup. The answer
	// lands later as kMsgHomeGeoResult and is folded into every subsequent
	// status broadcast so the map can plant a "you are here" pin.
	_KickHomeGeoLookup();

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
		case kMsgRequestVPNGate:
			_HandleRequestVPNGate(message);
			break;
		case kMsgConnectVPNGate:
			_HandleConnectVPNGate(message);
			break;

		// --- Internal: VPNGate catalogue arrived from the fetcher --------
		case kMsgVPNGateFetched:
			_HandleVPNGateFetched(message);
			break;

		// --- Events from the backend (we are its observer) -------------
		// The backend addresses these to us; we fan them out to clients.
		// The backend only knows about the VPN session itself, so we fold
		// in the home-geo and connected-host fields here -- otherwise the
		// map would lose the self pin and the connection arc on every
		// state change (the only path that carries them today is the
		// one-shot GetStatus reply via _FillStatus).
		case kMsgStatusUpdate:
			_HandleStatusForNotification(message);
			_EnrichForBroadcast(message);
			_Broadcast(message);
			break;
		case kMsgStatsUpdate:
			_EnrichForBroadcast(message);
			_Broadcast(message);
			break;

		// --- Internal: country lookup result ---------------------------
		case kMsgCountryResult:
			_HandleCountryResult(message);
			break;
		case kMsgHomeGeoResult:
			_HandleHomeGeoResult(message);
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
		// A VPNGate connect optimistically recorded the host before getting
		// here; the connect never happened, so drop it or later broadcasts
		// would advertise a session we never started.
		fConnectedHost = "";
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
		// Connect failed synchronously, so the backend never entered (and
		// will never leave) an ERROR/DISCONNECTED state -- the notification
		// path that normally clears fConnectedHost won't run. Clear it here
		// so a failed VPNGate connect doesn't leave the map arced to a host
		// with no live session.
		fConnectedHost = "";
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

	// Home geo (constant across status updates; cheap to fold in so a fresh
	// subscriber doesn't have to wait for the next disconnect to learn it).
	if (fHomeCountry.Length() > 0)
		message->AddString(kFieldHomeCountry, fHomeCountry);
	if (fHomeIP.Length() > 0)
		message->AddString(kFieldHomeIP, fHomeIP);
	if (fHomeLat != 0.0f || fHomeLon != 0.0f) {
		message->AddFloat(kFieldHomeLat, fHomeLat);
		message->AddFloat(kFieldHomeLon, fHomeLon);
	}

	// vpngate host the user is currently aimed at, if any. The map uses
	// this to draw the connection arc to the right pin.
	if (fConnectedHost.Length() > 0)
		message->AddString(kFieldConnectedHost, fConnectedHost);
}


void
SotoportegoServer::_EnrichForBroadcast(BMessage* message)
{
	// Only adds fields that aren't already present, since the backend may
	// have set some of them (e.g. localIP/remoteIP). The map-relevant ones
	// (home position, connected host) the backend never knows about.
	if (message->FindString(kFieldHomeCountry, (const char**)NULL) != B_OK
			&& fHomeCountry.Length() > 0)
		message->AddString(kFieldHomeCountry, fHomeCountry);
	if (message->FindString(kFieldHomeIP, (const char**)NULL) != B_OK
			&& fHomeIP.Length() > 0)
		message->AddString(kFieldHomeIP, fHomeIP);
	float dummy;
	if (message->FindFloat(kFieldHomeLat, &dummy) != B_OK
			&& (fHomeLat != 0.0f || fHomeLon != 0.0f)) {
		message->AddFloat(kFieldHomeLat, fHomeLat);
		message->AddFloat(kFieldHomeLon, fHomeLon);
	}
	if (message->FindString(kFieldConnectedHost, (const char**)NULL) != B_OK
			&& fConnectedHost.Length() > 0)
		message->AddString(kFieldConnectedHost, fConnectedHost);
}


void
SotoportegoServer::_KickHomeGeoLookup()
{
	if (fHomeLookupInFlight)
		return;
	// Only resolve the home location when we are not currently routing
	// through a VPN -- otherwise ip-api answers with the VPN exit address
	// and we'd remember that as "home".
	if (fBackend != NULL && fBackend->State() != VPN_STATE_DISCONNECTED
			&& fBackend->State() != VPN_STATE_ERROR) {
		return;
	}
	fHomeLookupInFlight = true;
	GeoLookup::BackgroundLookup(BMessenger(this), kMsgHomeGeoResult);
}


void
SotoportegoServer::_HandleHomeGeoResult(BMessage* message)
{
	fHomeLookupInFlight = false;

	const char* country = NULL;
	const char* ip = NULL;
	float lat = 0.0f;
	float lon = 0.0f;
	message->FindString(GeoLookup::kFieldCountry, &country);
	message->FindString(GeoLookup::kFieldQueryIP, &ip);
	message->FindFloat(GeoLookup::kFieldLatitude, &lat);
	message->FindFloat(GeoLookup::kFieldLongitude, &lon);

	bool changed = false;
	if (country != NULL && fHomeCountry != country) {
		fHomeCountry = country;
		changed = true;
	}
	if (ip != NULL && fHomeIP != ip) {
		fHomeIP = ip;
		changed = true;
	}
	if (lat != 0.0f && lon != 0.0f
			&& (lat != fHomeLat || lon != fHomeLon)) {
		fHomeLat = lat;
		fHomeLon = lon;
		changed = true;
	}

	if (!changed)
		return;

	printf("[server] home geo: %s / %s / %.3f, %.3f\n",
		fHomeCountry.String(), fHomeIP.String(), fHomeLat, fHomeLon);

	// Refresh every subscriber so the map can update its self pin.
	BMessage update(kMsgStatusUpdate);
	_FillStatus(&update);
	_Broadcast(&update);
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

	// Whenever the daemon ends up in a non-live state, drop the
	// connected-host record unconditionally. The notification logic
	// below still gates on the transition (so we don't post duplicate
	// "VPN disconnected" balloons), but the broadcast field has to be
	// cleared even when DISCONNECTED -> DISCONNECTED is just a status
	// echo, otherwise the map keeps drawing the arc to the previous pin
	// after the catalogue arrives.
	if (newState == VPN_STATE_DISCONNECTED || newState == VPN_STATE_ERROR) {
		fConnectedHost = "";
		fLastServerSummary = "";
	}

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
			fConnectedHost = "";
			// Routing is back on the carrier; refresh "home" so the map
			// reflects the user's actual position if they moved networks.
			_KickHomeGeoLookup();
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
			fConnectedHost = "";
			_KickHomeGeoLookup();
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
		country = "";
	}
	const char* externalIP = NULL;
	if (message->FindString(GeoLookup::kFieldQueryIP, &externalIP) != B_OK
			|| externalIP == NULL) {
		externalIP = "";
	}

	// Need at least one of the two to be useful.
	if (country[0] == '\0' && externalIP[0] == '\0')
		return;

	// Server on the first line, country alone on the second -- the
	// context makes the label redundant and the country is the part
	// the eye lands on.
	BString content("Connected to ");
	if (fLastServerSummary.Length() > 0)
		content << fLastServerSummary;
	else
		content << "VPN";
	if (country[0] != '\0') {
		content << "\n";
		content << country;
	}
	_PostNotification("Sotoportego", content.String(),
		B_INFORMATION_NOTIFICATION);

	// Also push a status update so subscribed clients (the GUI) can
	// surface the country / external IP in their own UI. Reuses
	// _FillStatus so the payload looks like any other status broadcast
	// plus the geo fields.
	BMessage update(kMsgStatusUpdate);
	_FillStatus(&update);
	if (country[0] != '\0')
		update.AddString(kFieldCountry, country);
	if (externalIP[0] != '\0')
		update.AddString(kFieldExternalIP, externalIP);
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


// --- VPNGate catalogue ----------------------------------------------------

void
SotoportegoServer::_HandleRequestVPNGate(BMessage* message)
{
	BMessenger client = _ClientFrom(message);
	if (!client.IsValid())
		return;

	// Honour the cache only if the requester didn't ask for a refresh.
	bool force = false;
	if (message->FindBool("force", &force) != B_OK)
		force = false;

	bigtime_t now = system_time();
	if (!force && fCatalogueFetchedAt > 0
			&& (now - fCatalogueFetchedAt) < kCatalogueTTL
			&& fCatalogueCache.CountNames(B_ANY_TYPE) > 0) {
		client.SendMessage(&fCatalogueCache);
		return;
	}

	fCataloguePending.push_back(client);
	if (!fCatalogueFetchInFlight)
		_KickVPNGateFetch();
}


void
SotoportegoServer::_KickVPNGateFetch()
{
	fCatalogueFetchInFlight = true;
	printf("[server] fetching VPNGate catalogue\n");
	VPNGateFetcher::BackgroundFetch(BMessenger(this), kMsgVPNGateFetched);
}


void
SotoportegoServer::_HandleVPNGateFetched(BMessage* message)
{
	fCatalogueFetchInFlight = false;

	// Build the reply once, then ship it to everyone waiting. Reusing
	// fCatalogueCache as the reply means a follow-up cache hit is just a
	// pointer pass.
	fCatalogueCache.MakeEmpty();
	fCatalogueCache.what = kMsgVPNGateList;

	BMessage entry;
	for (int32 i = 0; message->FindMessage(kFieldVPNGateServer, i, &entry)
			== B_OK; i++) {
		fCatalogueCache.AddMessage(kFieldVPNGateServer, &entry);
	}
	const char* error = NULL;
	if (message->FindString(kFieldError, &error) == B_OK && error != NULL)
		fCatalogueCache.AddString(kFieldError, error);

	fCatalogueFetchedAt = system_time();

	for (size_t i = 0; i < fCataloguePending.size(); i++)
		fCataloguePending[i].SendMessage(&fCatalogueCache);
	fCataloguePending.clear();
}


// Minimal RFC 4648 base64 decoder. Returns true on success and writes the
// raw bytes into `out`; returns false if `in` contains stray characters or
// has invalid padding.
static bool
decode_base64(const char* in, std::string& out)
{
	static const int kTable[256] = {
		// Initialise to -1 by relying on C++ zero-init then patch the valid
		// alphabet at runtime once. The compiler still folds this into a
		// table; clarity beats premature golf.
		-2
	};
	static int kReady = 0;
	static int kReal[256];
	if (!kReady) {
		for (int i = 0; i < 256; i++)
			kReal[i] = -1;
		const char* alpha =
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		for (int i = 0; i < 64; i++)
			kReal[(unsigned char)alpha[i]] = i;
		kReady = 1;
	}
	(void)kTable;

	int buffer = 0;
	int bits = 0;
	out.clear();
	for (const char* p = in; *p; p++) {
		unsigned char c = (unsigned char)*p;
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
			continue;
		if (c == '=')
			break;
		int v = kReal[c];
		if (v < 0)
			return false;
		buffer = (buffer << 6) | v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out.push_back((char)((buffer >> bits) & 0xFF));
		}
	}
	return true;
}


BString
SotoportegoServer::_WriteVPNGateConfig(const char* host,
	const char* base64Body)
{
	if (host == NULL || base64Body == NULL)
		return BString();

	BPath dir;
	if (find_directory(B_USER_CACHE_DIRECTORY, &dir) != B_OK)
		return BString();
	dir.Append("Sotoportego");
	dir.Append("vpngate");
	create_directory(dir.Path(), 0755);

	// Sanitise the host name into a filename: only ASCII alnum, dot, dash,
	// underscore. Anything else gets replaced with '_' so we can't be
	// tricked into walking out of the cache dir with "../../etc/passwd".
	BString safe;
	for (int32 i = 0; host[i] != '\0'; i++) {
		char c = host[i];
		bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			|| (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
		safe << (ok ? c : '_');
	}
	if (safe.Length() == 0)
		safe = "server";
	safe << ".ovpn";

	BPath out(dir.Path());
	out.Append(safe.String());

	std::string decoded;
	if (!decode_base64(base64Body, decoded) || decoded.empty()) {
		printf("[server] vpngate: base64 decode failed for %s\n", host);
		return BString();
	}

	BFile file(out.Path(), B_WRITE_ONLY | B_CREATE_FILE | B_ERASE_FILE);
	if (file.InitCheck() != B_OK)
		return BString();
	if (file.Write(decoded.data(), decoded.size()) != (ssize_t)decoded.size())
		return BString();

	return BString(out.Path());
}


void
SotoportegoServer::_HandleConnectVPNGate(BMessage* message)
{
	if (fBackend == NULL)
		return;

	const char* host = NULL;
	const char* base64 = NULL;
	const char* ccLong = NULL;
	if (message->FindString(kFieldVPNGateHost, &host) != B_OK || host == NULL
			|| message->FindString(kFieldVPNGateConfigBase64, &base64) != B_OK
			|| base64 == NULL) {
		printf("[server] connect-vpngate rejected: missing host/config\n");
		return;
	}
	message->FindString(kFieldVPNGateCountryLong, &ccLong);

	// Record the host now so the next status broadcast (and the geo
	// result that lands later) can carry it. Cleared by the disconnect
	// path below.
	fConnectedHost = host;

	BString configPath = _WriteVPNGateConfig(host, base64);
	if (configPath.Length() == 0) {
		// Staging failed, so the connect won't happen -- undo the optimistic
		// host record set just above.
		fConnectedHost = "";
		BMessage reply(kMsgStatusUpdate);
		_FillStatus(&reply);
		reply.AddString(kFieldDetail, "could not stage vpngate .ovpn");
		BMessenger client = _ClientFrom(message);
		if (client.IsValid())
			client.SendMessage(&reply);
		return;
	}

	// Synthesize a one-shot in-memory VPNProfile pointing at the staged
	// .ovpn and reuse the standard Connect message. This keeps the
	// backend ignorant of where the profile came from.
	VPNProfile profile;
	profile.fBackendType = VPN_BACKEND_OPENVPN;
	profile.fName << "VPNGate " << host;
	if (ccLong != NULL && ccLong[0] != '\0')
		profile.fName << " (" << ccLong << ")";
	profile.fServer = host;
	profile.fPort = 443;	// nominal; openvpn picks the real one from the .ovpn
	profile.fConfigPath = configPath;

	BMessage archive;
	profile.Archive(&archive);

	BMessage connect(kMsgConnect);
	connect.AddMessage(kFieldProfile, &archive);

	BMessenger client = _ClientFrom(message);
	if (client.IsValid())
		connect.AddMessenger(kFieldClient, client);
	const char* user = NULL;
	const char* pass = NULL;
	if (message->FindString(kFieldUsername, &user) == B_OK && user != NULL)
		connect.AddString(kFieldUsername, user);
	if (message->FindString(kFieldPassword, &pass) == B_OK && pass != NULL)
		connect.AddString(kFieldPassword, pass);

	_HandleConnect(&connect);
}
