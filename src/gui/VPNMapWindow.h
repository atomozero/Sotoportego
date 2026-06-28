/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef VPN_MAP_WINDOW_H
#define VPN_MAP_WINDOW_H


#include <Messenger.h>
#include <String.h>
#include <Window.h>

#include <map>

class BBox;
class BButton;
class BColumnListView;
class BStringView;
class MapView;
class MetricPill;


// Standalone window that hosts the world MapView and a side panel
// describing whichever server pin is currently selected. The eventual
// goal is a one-click way to connect to a public VPNGate server: pick a
// pin, see its host / country / ping / score / load, hit Connect, the
// daemon fetches the .ovpn body for that host and reuses the existing
// OpenVPN flow.
//
// This first cut is the wiring shell: the toolbar and side panel are
// real, but the catalogue is a hardcoded handful of test pins so the
// rendering, selection and panel-refresh paths can be exercised before
// the daemon-side VPNGate fetcher lands (tracked separately).
//
// Like the rest of the GUI, the window is just another BMessage client
// of the daemon: future revisions will subscribe to kMsgVPNGateList for
// the catalogue, and the Connect button will dispatch a
// kMsgConnectVPNGate request, but neither protocol code exists yet.
class VPNMapWindow : public BWindow {
public:
								VPNMapWindow();

	virtual	void				MessageReceived(BMessage* message);

private:
			void				_BuildLayout();
			void				_RefreshSidePanel();

	// Cluster drill-down: kMsgClusterSelected carries one repeated
	// (host, country, ping, score, sessions, logPolicy) tuple per
	// member; _ApplyCluster reads them all into fClusterList and shows
	// fClusterBox. Picking a row promotes that host to the live map
	// selection (via _PickClusterRow) so the Server panel + Connect
	// button keep working as for a single-pin click. The list hides
	// itself again on Close, on Disconnect-to-elsewhere, or when a
	// new single-pin click invalidates the previous cluster.
			void				_ApplyCluster(const BMessage* message);
			void				_PickClusterRow();
			void				_HideCluster();

	// Daemon plumbing.
			void				_EnsureDaemon();
			void				_RequestCatalogue(bool force);
			void				_ApplyCatalogue(BMessage* message);
			void				_BeginConnectFlow();
			void				_SendConnectWith(const char* user,
									const char* pass);

			MapView*			fMap;
	// Drill-down list shown below the Server side panel when the user
	// clicks a cluster pin (count > 1 servers rendered onto the same
	// pixel). Hidden until kMsgClusterSelected lands. Row click sets the
	// chosen host as the live map selection so the Server panel + Connect
	// button work exactly as for a single-pin click.
			BBox*				fClusterBox;
			BColumnListView*	fClusterList;

			BStringView*		fHostValue;
			BStringView*		fCountryValue;
			MetricPill*			fPingValue;
			MetricPill*			fScoreValue;
			MetricPill*			fSessionsValue;
			BStringView*		fLogPolicyValue;
			BStringView*		fStatusBar;
			BButton*			fConnectButton;

	// Messenger we use to talk to the daemon. Lazily resolved on first use
	// so we don't block opening the window when the server is slow.
			BMessenger			fServer;
	// host string -> base64 ovpn body, kept so that Connect can ship the
	// staging payload without re-fetching the whole catalogue.
			std::map<BString, BString>	fOvpnByHost;
};


#endif	// VPN_MAP_WINDOW_H
