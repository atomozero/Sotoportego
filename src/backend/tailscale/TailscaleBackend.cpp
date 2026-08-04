/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TailscaleBackend.h"

#include <stdio.h>

#include <Messenger.h>

#include "VPNProfile.h"

#include "TSControl.h"			// kControlProtocolVersion
#include "TSControlSession.h"
#include "TSMap.h"
#include "TSRegister.h"


// Private messages the control worker posts back to the looper.
static const uint32 kMsgTsAuthURL		= 'tsAu';	// "url"
static const uint32 kMsgTsAuthorized	= 'tsOk';
static const uint32 kMsgTsFailed		= 'tsEr';	// "detail" (empty == stopped)
static const uint32 kMsgTsNetmap		= 'tsNm';	// "peers" int32, "selfip"

// Default coordination server when a profile doesn't name one.
static const char* const kDefaultControlHost = "controlplane.tailscale.com";


TailscaleBackend::TailscaleBackend()
	:
	VPNBackend("tailscale_backend"),
	fState(VPN_STATE_DISCONNECTED),
	fStats(),
	fLocalIP(""),
	fRemoteIP(""),
	fControlHost(""),
	fHostname(""),
	fAuthKey(""),
	fWorker(-1),
	fStopRequested(false)
{
}


TailscaleBackend::~TailscaleBackend()
{
	_StopWorker();
}


status_t
TailscaleBackend::Connect(const VPNProfile& profile)
{
	if (profile.fName.Length() == 0) {
		_SetState(VPN_STATE_ERROR, "Tailscale profile has no name");
		return B_BAD_VALUE;
	}
	if (fWorker >= 0) {
		_SetState(VPN_STATE_ERROR, "a Tailscale connection is already in flight");
		return B_NOT_ALLOWED;
	}

	// Phase 1: establish this node's persistent identity (machine/node/disco
	// keys), loaded from the keystore or minted and stored on first use.
	bool createdAny = false;
	status_t result = fIdentity.LoadOrCreate(profile.fName.String(),
		&createdAny);
	if (result != B_OK) {
		_SetState(VPN_STATE_ERROR, "could not establish node identity");
		return result;
	}
	BString nodePub = ts::TSIdentity::ToHex(fIdentity.NodePublic(), 32);
	printf("[tailscale] identity ready for '%s' (%s) node:%s\n",
		profile.fName.String(), createdAny ? "generated" : "reused",
		nodePub.String());

	// Snapshot what the worker needs so the thread never touches the profile.
	// fServer carries the control host for a Tailscale profile; default to the
	// public coordination server. The tailnet hostname defaults to the profile
	// name.
	if (profile.fServer.Length() > 0)
		fControlHost = profile.fServer;
	else
		fControlHost = kDefaultControlHost;
	fHostname = profile.fName;
	fAuthKey = "";	// TODO: read an optional pre-auth key from TSConfig

	fStopRequested = false;
	_SetState(VPN_STATE_CONNECTING);
	_StartWorker();
	if (fWorker < 0) {
		_SetState(VPN_STATE_ERROR, "could not start the Tailscale control worker");
		return B_ERROR;
	}
	return B_OK;
}


status_t
TailscaleBackend::Disconnect()
{
	// Ask the worker to stop; it posts kMsgTsFailed("") when it unwinds, which
	// settles the state on Disconnected. If no worker is running, drop straight
	// to Disconnected.
	fStopRequested = true;
	if (fWorker < 0)
		_SetState(VPN_STATE_DISCONNECTED);
	return B_OK;
}


VPNState
TailscaleBackend::State() const
{
	return fState;
}


VPNStats
TailscaleBackend::Stats() const
{
	return fStats;
}


const char*
TailscaleBackend::BackendName() const
{
	return "Tailscale";
}


BString
TailscaleBackend::LocalIP() const
{
	return fLocalIP;
}


BString
TailscaleBackend::RemoteIP() const
{
	return fRemoteIP;
}


void
TailscaleBackend::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgTsAuthURL:
		{
			// Interactive login required: surface the URL so the GUI can show
			// (and open) it. Stay in AUTHENTICATING while we poll.
			const char* url = NULL;
			if (message->FindString("url", &url) == B_OK && url != NULL) {
				printf("[tailscale] auth required: %s\n", url);
				_SetState(VPN_STATE_AUTHENTICATING, url);
			}
			break;
		}

		case kMsgTsAuthorized:
			// Control authorized; the worker now long-polls the network map.
			printf("[tailscale] node authorized; fetching network map\n");
			_SetState(VPN_STATE_AUTHENTICATING, "authorized -- fetching network map");
			break;

		case kMsgTsNetmap:
		{
			// A MapResponse was applied. Report the netmap summary. The packet
			// data plane (magicsock reader + tun) isn't wired yet, so this is
			// not a full CONNECTED tunnel -- reflect that in the detail.
			int32 peers = 0;
			const char* selfip = NULL;
			message->FindInt32("peers", &peers);
			if (message->FindString("selfip", &selfip) == B_OK && selfip != NULL)
				fLocalIP = selfip;
			BString detail;
			detail.SetToFormat("netmap: %d peer%s%s%s (data plane pending)",
				(int)peers, peers == 1 ? "" : "s",
				(selfip && *selfip) ? ", self " : "",
				(selfip && *selfip) ? selfip : "");
			printf("[tailscale] %s\n", detail.String());
			_SetState(VPN_STATE_AUTHENTICATING, detail.String());
			break;
		}

		case kMsgTsFailed:
		{
			fWorker = -1;
			const char* detail = NULL;
			if (message->FindString("detail", &detail) != B_OK)
				detail = NULL;
			if (detail == NULL || *detail == '\0')
				_SetState(VPN_STATE_DISCONNECTED);
			else
				_SetState(VPN_STATE_ERROR, detail);
			break;
		}

		default:
			VPNBackend::MessageReceived(message);
			break;
	}
}


void
TailscaleBackend::_StartWorker()
{
	fWorker = spawn_thread(_WorkerEntry, "tailscale-control",
		B_NORMAL_PRIORITY, this);
	if (fWorker < B_OK) {
		fWorker = -1;
		fprintf(stderr, "[tailscale] spawn_thread failed\n");
		return;
	}
	resume_thread(fWorker);
}


void
TailscaleBackend::_StopWorker()
{
	fStopRequested = true;
	if (fWorker >= 0) {
		status_t ignored;
		wait_for_thread(fWorker, &ignored);
		fWorker = -1;
	}
}


int32
TailscaleBackend::_WorkerEntry(void* self)
{
	return ((TailscaleBackend*)self)->_RunControlFlow();
}


int32
TailscaleBackend::_RunControlFlow()
{
	BMessenger self(this);
	uint16 version = ts::kControlProtocolVersion;

	ts::ControlSession session;
	ts::RegisterResult res;
	status_t result = session.Connect(fControlHost.String(), 443,
		false /* verify TLS */, version,
		fIdentity.MachinePrivate(), fIdentity.MachinePublic(),
		fIdentity.NodePublic(), fHostname.String(),
		fAuthKey.Length() > 0 ? fAuthKey.String() : NULL, res);

	if (fStopRequested) {
		BMessage m(kMsgTsFailed);
		m.AddString("detail", "");
		self.SendMessage(&m);
		return 0;
	}
	if (result != B_OK) {
		BMessage m(kMsgTsFailed);
		m.AddString("detail", session.LastError());
		self.SendMessage(&m);
		return 0;
	}
	if (res.error.Length() > 0) {
		BMessage m(kMsgTsFailed);
		m.AddString("detail", res.error.String());
		self.SendMessage(&m);
		return 0;
	}
	if (res.machineAuthorized) {
		self.SendMessage(kMsgTsAuthorized);
		_RunMap(session, self);
		return 0;
	}
	if (res.authURL.Length() == 0) {
		BMessage m(kMsgTsFailed);
		m.AddString("detail", "control returned neither authorization nor a "
			"login URL");
		self.SendMessage(&m);
		return 0;
	}

	// Interactive login: surface the URL and long-poll to authorized.
	{
		BMessage m(kMsgTsAuthURL);
		m.AddString("url", res.authURL.String());
		self.SendMessage(&m);
	}

	BString followup = res.authURL;
	while (!fStopRequested) {
		ts::RegisterResult pr;
		status_t pollResult = session.PollAuthorized(fControlHost.String(),
			version, fIdentity.NodePublic(), fHostname.String(),
			followup.String(), pr);
		if (fStopRequested)
			break;
		if (pollResult != B_OK) {
			BMessage m(kMsgTsFailed);
			m.AddString("detail", session.LastError());
			self.SendMessage(&m);
			return 0;
		}
		if (pr.error.Length() > 0) {
			BMessage m(kMsgTsFailed);
			m.AddString("detail", pr.error.String());
			self.SendMessage(&m);
			return 0;
		}
		if (pr.machineAuthorized) {
			self.SendMessage(kMsgTsAuthorized);
			_RunMap(session, self);
			return 0;
		}
		if (pr.authURL.Length() > 0)
			followup = pr.authURL;	// server may hand us a fresh followup URL
	}

	BMessage m(kMsgTsFailed);
	m.AddString("detail", "");	// stopped
	self.SendMessage(&m);
	return 0;
}


void
TailscaleBackend::_RunMap(ts::ControlSession& session, BMessenger& self)
{
	uint16 version = ts::kControlProtocolVersion;

	ts::MapStream map;
	int status = 0;
	status_t result = map.Begin(session.Http2(), fControlHost.String(), version,
		fIdentity.NodePublic(), fHostname.String(), &status);
	if (result != B_OK || status != 200) {
		BMessage m(kMsgTsFailed);
		BString detail;
		detail.SetToFormat("network map request failed (HTTP %d)", status);
		m.AddString("detail", detail.String());
		self.SendMessage(&m);
		return;
	}

	// Stream MapResponses: the first is the full snapshot, then deltas. Apply
	// each to the session state and post a netmap summary.
	BString msg;
	while (!fStopRequested) {
		status_t r = map.ReadMessage(msg);
		if (r == B_ENTRY_NOT_FOUND)
			break;	// clean end of stream
		if (r != B_OK) {
			if (fStopRequested)
				break;
			// A read error (e.g. control drop) ends the map session.
			BMessage m(kMsgTsFailed);
			m.AddString("detail", "network map stream ended");
			self.SendMessage(&m);
			return;
		}
		if (!fSession.ApplyMapResponse(msg.String(), msg.Length()))
			continue;	// skip a malformed message, keep the stream

		BMessage nm(kMsgTsNetmap);
		nm.AddInt32("peers", fSession.PeerCount());
		nm.AddString("selfip", fSession.SelfIPv4());
		self.SendMessage(&nm);
	}

	BMessage done(kMsgTsFailed);
	done.AddString("detail", "");	// stopped
	self.SendMessage(&done);
}


void
TailscaleBackend::RecoverIfCrashed()
{
	// Nothing to roll back yet: no tun slot, routes or resolv.conf are touched
	// until the data-plane phases land. Once they do, this mirrors
	// WireGuardBackend::RecoverIfCrashed() (tun/route/DNS teardown from a
	// recorded session file).
}


void
TailscaleBackend::_SetState(VPNState state, const char* detail)
{
	fState = state;
	NotifyStateChanged(state, detail);
}
