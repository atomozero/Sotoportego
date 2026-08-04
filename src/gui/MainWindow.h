/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef MAIN_WINDOW_H
#define MAIN_WINDOW_H


#include <Messenger.h>
#include <String.h>
#include <Window.h>

#include <vector>

#include "VPNProfile.h"
#include "VPNState.h"

class BButton;
class BFilePanel;
class BListView;
class BMessageRunner;
class BStringView;
class HeaderView;


// Automation hooks: posting these to the main window runs the same connect /
// disconnect paths as the menu items. Used by the app's `hey` scripting suite
// so the two commands are drivable from a script or the command line.
static const uint32 kMsgAutomationConnect		= 'auCo';
static const uint32 kMsgAutomationDisconnect	= 'auDi';


// The main Sotoportego window. Like the CLI, it is purely a client of the
// daemon: it subscribes over BMessage, reflects the broadcast state/stats, and
// sends connect/disconnect requests. No VPN logic lives here.
//
// Visual layout, top to bottom:
//   * BMenuBar
//   * HeaderView (slate banner, brand tile + status dot + metadata)
//   * BTabView ("Connection" / "Statistics")
//   * status BStringView (compact bottom line)
class MainWindow : public BWindow {
public:
								MainWindow();
	virtual						~MainWindow();

	virtual	void				MessageReceived(BMessage* message);

private:
			void				_BuildLayout();
			BView*				_BuildConnectionTab();
			BView*				_BuildStatisticsTab();
			void				_EnsureSubscribed();
			void				_SendConnect();
			void				_SendDisconnect();
			void				_UpdateForState(VPNState state,
									const char* detail);
		// Open a Tailscale interactive-login AuthURL found in the status detail,
		// once per distinct URL (fLastAuthURL guards against reopening on every
		// status tick).
				void				_MaybeOpenAuthURL(const char* detail);
			void				_ApplyStats(const BMessage* message);
		// Cache the Tailscale peer list from a status broadcast and refresh
		// the peers window if it is open.
			void				_UpdatePeers(const BMessage* status);
			void				_AppendEvent(const char* text);
	// Rebuild the bottom status-bar line. Called from _UpdateForState
	// and from the 1 Hz uptime tick.
			void				_RefreshStatusBar();
			void				_StartUptimeTimer();
			void				_StopUptimeTimer();

	// Profile management.
			void				_ApplyProfileList(const BMessage* message);
			void				_RefreshProfileList();
			void				_RefreshDetails();
			void				_OpenImportPanel();
			void				_ImportFile(const entry_ref& ref);
		// Create and save a Tailscale profile (VPN_BACKEND_TAILSCALE) from the
		// name + control-server URL the Tailscale dialog collected.
			void				_CreateTailscaleProfile(const char* name,
									const char* controlURL,
									const char* authKey);
			void				_DeleteSelectedProfile();
			const VPNProfile*	_SelectedProfile() const;

	// Connect flow: prompt for credentials if the profile needs them, then
	// dispatch Connect with whatever the user provided.
			void				_BeginConnectFlow();
			void				_SendConnectWith(const char* username,
									const char* password);

	// "Forget saved password" affordance and its automatic counterpart:
	// when an in-flight Connect with stored credentials lands in ERROR
	// with "authentication failed", drop them so the next Connect
	// prompts again instead of looping on the same bad secret.
			void				_ForgetSelectedPassword();

	// Deskbar replicant install/uninstall, wired to the Tools menu.
	// Failures are reported via a BAlert so the user isn't left
	// wondering whether the click did anything.
			void				_InstallDeskbarIcon();
			void				_RemoveDeskbarIcon();

	static	BString				_FormatBytes(int64 bytes);

			BMessenger			fServer;
			VPNState			fState;

			HeaderView*			fHeader;
			BStringView*		fServerLabel;
			BStringView*		fBackendLabel;
			BStringView*		fProtocolLabel;
			BStringView*		fTunnelIPValue;
			BStringView*		fExternalIPValue;
			BStringView*		fConnNotice;
			BStringView*		fSinceValue;
			BStringView*		fDownValue;
			BStringView*		fUpValue;
			BListView*			fProfileList;
			BListView*			fEventLog;
			BButton*			fAddButton;
			BButton*			fRemoveButton;
			BButton*			fActionButton;
			BStringView*		fStatusBar;

	// When the daemon reports CONNECTED we start ticking the status bar
	// once a second so the user sees the session uptime grow ("Connected
	// · 00:12:34"). fConnectedSince is the wall-clock epoch the daemon
	// captured on CONNECTED; fUptimeTimer is a 1 Hz BMessageRunner that
	// posts kMsgUptimeTick to us, alive only while the state is live.
			time_t				fConnectedSince;
			BMessageRunner*		fUptimeTimer;

			BFilePanel*			fImportPanel;
			std::vector<VPNProfile>	fProfiles;
			BString					fSelectedName;
	// Apparent egress country, broadcast by the daemon after the
	// geo-lookup completes. Empty before that lookup lands and cleared
	// on every Disconnect.
			BString					fCountry;

	// Name of the profile we last sent kMsgConnect with, plus whether
	// we used a keystore-stored password for it. Together they tell
	// the auth-failure path whether (and which) stored credentials to
	// clear so we don't loop on a stale secret.
			BString					fLastConnectProfile;
			bool					fLastUsedStoredCredentials;

		// The last Tailscale AuthURL we opened, so the browser isn't relaunched
		// on every AUTHENTICATING status update carrying the same URL.
			BString					fLastAuthURL;

		// The peers window (a messenger so we can tell whether it's still
		// open) plus the latest peer snapshot pushed to it on every status
		// update.
			BMessenger				fPeersWindow;
			BMessage				fLastPeers;

		// The profile the daemon reports as actually connected (broadcast in
		// the status), so the Server box describes the live session rather than
		// the list selection. fHasConnectedProfile is false while idle.
			VPNProfile				fConnectedProfile;
			bool					fHasConnectedProfile;
};


#endif	// MAIN_WINDOW_H
