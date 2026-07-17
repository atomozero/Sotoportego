/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef SOTOPORTEGO_SERVER_H
#define SOTOPORTEGO_SERVER_H


#include <vector>

#include <Application.h>
#include <Messenger.h>
#include <String.h>

#include "ProfileStore.h"
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
			void				_HandleSaveProfile(BMessage* message);
			void				_HandleDeleteProfile(BMessage* message);

	// Copy an imported OpenVPN .ovpn into the daemon's own config store and
	// repoint the profile at the copy, so a saved profile keeps working after
	// the user moves or deletes the file they imported from. No-op for
	// non-OpenVPN profiles, an empty path, or a path already in the store.
			void				_StageImportedConfig(VPNProfile& profile);
			void				_HandleRequestVPNGate(BMessage* message);
			void				_HandleConnectVPNGate(BMessage* message);

	// VPNGate catalogue lifecycle: when a client asks for it we either
	// return the cached copy or queue them up behind one in-flight fetcher
	// thread; when the thread comes back we reply to every queued client.
			void				_HandleVPNGateFetched(BMessage* message);
			void				_KickVPNGateFetch();

	// Decode `base64Body` and write it to a fresh .ovpn file inside the
	// daemon's cache dir. `host` is used to name the file. Returns the
	// final path on success, an empty BString on failure.
			BString				_WriteVPNGateConfig(const char* host,
									const char* base64Body);

	// Watch incoming status updates for the transitions that warrant a
	// desktop notification (Connected, Disconnected, Error) and fan them
	// out via BNotification. The Connected notification kicks off a
	// background geo-lookup that updates it with the apparent country
	// once the answer comes back.
			void				_HandleStatusForNotification(
									BMessage* message);
			void				_HandleCountryResult(BMessage* message);
			void				_HandleHomeGeoResult(BMessage* message);
			void				_KickHomeGeoLookup();
			void				_PostNotification(const char* title,
									const char* content, int32 type = 0);

	// Re-broadcast a backend event (state or stats) to every subscribed
	// client, pruning any that have gone away.
			void				_Broadcast(BMessage* message);

	// Build a fresh status snapshot from the backend.
			void				_FillStatus(BMessage* message);

	// Fold home-geo and connected-host fields into a backend-originated
	// status/stats broadcast so subscribed clients (notably the map) keep
	// seeing them after the initial GetStatus reply.
			void				_EnrichForBroadcast(BMessage* message);

	// Build and broadcast a kMsgListProfiles snapshot. Sent to a specific
	// client on subscribe and to everyone after a profile-store mutation.
			void				_SendProfileList(BMessenger to) const;
			void				_BroadcastProfileList();

			BMessenger			_ClientFrom(BMessage* message) const;

			VPNBackend*				fBackend;
			ProfileStore			fProfiles;
			std::vector<BMessenger>	fClients;

	// Last broadcast state we observed, so we know which transitions just
	// happened and only fire notifications once per state change.
			VPNState				fLastState;
	// Last successful connection summary, kept so the
	// geo-lookup result can rebuild the same notification text plus the
	// country tag.
			BString					fLastServerSummary;
	// vpngate host currently being connected to, if the active session was
	// started via kMsgConnectVPNGate. Empty for sessions started from a
	// regular profile. Used so the map can highlight the right pin.
			BString					fConnectedHost;

	// "Home" geo: where ip-api places our underlying carrier when no VPN
	// is up. Filled in once at startup (and on every disconnect) and folded
	// into every status broadcast so subscribed clients can show a "you
	// are here" marker without their own lookup. fHomeLat == 0 && fHomeLon
	// == 0 means "not yet resolved" (or genuinely Null Island; we accept
	// the false negative there).
			BString					fHomeCountry;
			BString					fHomeIP;
			float					fHomeLat;
			float					fHomeLon;
	// Guard against multiple in-flight home lookups (the disconnect path
	// can fire several times in a row).
			bool					fHomeLookupInFlight;

	// VPNGate catalogue cache. Held as a fully-formed kMsgVPNGateList
	// message so a cache hit is just a SendMessage, no copying. Empty
	// when nothing has been fetched yet; populated by _HandleVPNGateFetched.
			BMessage				fCatalogueCache;
			bigtime_t				fCatalogueFetchedAt;
			bool					fCatalogueFetchInFlight;
	// Clients that asked for the catalogue while a fetch was running. They
	// all get the same reply once it lands.
			std::vector<BMessenger>	fCataloguePending;
};


#endif	// SOTOPORTEGO_SERVER_H
