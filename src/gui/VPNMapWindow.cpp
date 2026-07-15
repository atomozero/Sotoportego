/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "VPNMapWindow.h"

#include <stdio.h>

#include <Alert.h>
#include <Box.h>
#include <Button.h>
#include <ColumnListView.h>
#include <ColumnTypes.h>
#include <Font.h>
#include <LayoutBuilder.h>
#include <Menu.h>
#include <MenuBar.h>
#include <MenuItem.h>
#include <Message.h>
#include <OS.h>
#include <Roster.h>
#include <StringView.h>

#include "CredentialsWindow.h"
#include "MapView.h"
#include "MetricPill.h"
#include "VPNProtocol.h"
#include "VPNState.h"


// --- toolbar / private message codes ---------------------------------------

static const uint32 kMsgConnectPicked		= 'mwCo';
static const uint32 kMsgRefresh				= 'mwRf';
static const uint32 kMsgCredentialsOK		= 'mwCO';
static const uint32 kMsgCredentialsCancel	= 'mwCC';
static const uint32 kMsgClusterRowInvoked	= 'mwCR';


// --- VPNMapWindow ----------------------------------------------------------

VPNMapWindow::VPNMapWindow()
	:
	BWindow(BRect(120, 100, 1080, 720),
		"Browse servers on map",
		B_TITLED_WINDOW,
		B_AUTO_UPDATE_SIZE_LIMITS),
	fMap(NULL),
	fClusterBox(NULL),
	fClusterList(NULL),
	fHostValue(NULL),
	fCountryValue(NULL),
	fPingValue(NULL),
	fScoreValue(NULL),
	fSessionsValue(NULL),
	fLogPolicyValue(NULL),
	fStatusBar(NULL),
	fConnectButton(NULL),
	fServer(),
	fOvpnByHost()
{
	_BuildLayout();
	_RefreshSidePanel();
	_EnsureDaemon();
	_RequestCatalogue(false);

	// Subscribe to status broadcasts so the map can plant the "you are
	// here" pin (from kFieldHomeLat/Lon) and highlight the connected
	// server (from kFieldConnectedHost) without doing its own lookups.
	if (fServer.IsValid()) {
		BMessage subscribe(kMsgSubscribe);
		subscribe.AddMessenger(kFieldClient, BMessenger(this));
		fServer.SendMessage(&subscribe);
		BMessage status(kMsgGetStatus);
		status.AddMessenger(kFieldClient, BMessenger(this));
		fServer.SendMessage(&status);
	}
}


void
VPNMapWindow::_BuildLayout()
{
	// --- menu bar -------------------------------------------------------
	BMenuBar* menuBar = new BMenuBar("menubar");

	BMenu* mapMenu = new BMenu("Map");
	mapMenu->AddItem(new BMenuItem("Zoom in",
		new BMessage(kMsgZoomIn), '+'));
	mapMenu->AddItem(new BMenuItem("Zoom out",
		new BMessage(kMsgZoomOut), '-'));
	mapMenu->AddItem(new BMenuItem("Fit to pins",
		new BMessage(kMsgZoomFit), 'F'));
	mapMenu->AddSeparatorItem();
	mapMenu->AddItem(new BMenuItem("Toggle background tiles",
		new BMessage(kMsgToggleTiles), 'T'));
	mapMenu->AddItem(new BMenuItem("Refresh server list",
		new BMessage(kMsgRefresh), 'R'));
	mapMenu->AddSeparatorItem();
	mapMenu->AddItem(new BMenuItem("Close",
		new BMessage(B_QUIT_REQUESTED), 'W'));
	menuBar->AddItem(mapMenu);

	// --- map ------------------------------------------------------------
	fMap = new MapView("worldMap");

	// --- side panel: server details -------------------------------------
	BBox* detailsBox = new BBox("serverDetails");
	detailsBox->SetLabel("Server");

	fHostValue = new BStringView("hostValue", "\xe2\x80\x94");
	fHostValue->SetFont(be_bold_font);
	fCountryValue = new BStringView("countryValue", "\xe2\x80\x94");
	fCountryValue->SetFont(be_bold_font);
	// Ping / score / sessions become colored pills so the user can pick a
	// good server at a glance instead of mentally translating raw numbers.
	fPingValue = new MetricPill("pingValue");
	fScoreValue = new MetricPill("scoreValue");
	fSessionsValue = new MetricPill("sessionsValue");
	fLogPolicyValue = new BStringView("logPolicyValue", "\xe2\x80\x94");
	fLogPolicyValue->SetFont(be_bold_font);

	// Pin the side-panel BBox at a fixed width that's comfortable for the
	// longest hostnames vpngate publishes (~30 chars). With
	// B_AUTO_UPDATE_SIZE_LIMITS on the window, leaving the BBox free to
	// grow makes the whole window resize on every pin click; locking the
	// width here keeps the geometry stable and gives the map a constant
	// canvas to draw on.
	const float kPanelWidth = 340.0f;
	// Pin both width AND a generous min-height so the cluster list below
	// (with a "I want lots of space" max-size) can't push the Server
	// panel down to nothing once a cluster is shown. The number is the
	// natural height of the 6-row grid + insets; bump if a new field
	// gets added.
	detailsBox->SetExplicitMinSize(BSize(kPanelWidth, 200));
	detailsBox->SetExplicitMaxSize(BSize(kPanelWidth, B_SIZE_UNLIMITED));

	BLayoutBuilder::Grid<>(detailsBox, B_USE_DEFAULT_SPACING,
			B_USE_SMALL_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING, B_USE_BIG_INSETS,
			B_USE_DEFAULT_SPACING, B_USE_DEFAULT_SPACING)
		.Add(new BStringView("hostCaption", "Host:"), 0, 0)
		.Add(fHostValue, 1, 0)
		.Add(new BStringView("countryCaption", "Country:"), 0, 1)
		.Add(fCountryValue, 1, 1)
		.Add(new BStringView("pingCaption", "Ping:"), 0, 2)
		.Add(fPingValue, 1, 2)
		.Add(new BStringView("scoreCaption", "Score:"), 0, 3)
		.Add(fScoreValue, 1, 3)
		.Add(new BStringView("sessionsCaption", "Sessions:"), 0, 4)
		.Add(fSessionsValue, 1, 4)
		.Add(new BStringView("logPolicyCaption", "Log policy:"), 0, 5)
		.Add(fLogPolicyValue, 1, 5);

	fConnectButton = new BButton("connectPicked", "Connect",
		new BMessage(kMsgConnectPicked));
	fConnectButton->MakeDefault(true);
	fConnectButton->SetEnabled(false);

	// --- cluster drill-down list ---------------------------------------
	// Hidden until the user clicks a cluster (count > 1). The panel is
	// kPanelWidth-wide, so the columns are tuned for that budget; the
	// detail metadata that doesn't fit in a row (full country name,
	// log policy) is what the Server panel above already shows once a
	// row is picked, so we don't repeat it here.
	fClusterBox = new BBox("clusterBox");
	fClusterBox->SetLabel("Servers in this area");
	fClusterBox->SetExplicitMinSize(BSize(kPanelWidth, 0));
	fClusterBox->SetExplicitMaxSize(BSize(kPanelWidth, B_SIZE_UNLIMITED));

	// `false` for the 4th arg drops the horizontal scrollbar: hostnames
	// truncate-middle so we never need it, and the bar otherwise eats
	// real estate at the bottom of the box for nothing.
	fClusterList = new BColumnListView("clusterList",
		B_NAVIGABLE | B_WILL_DRAW | B_FRAME_EVENTS, B_FANCY_BORDER, false);
	fClusterList->AddColumn(new BStringColumn("Host", 180, 80, 600,
		B_TRUNCATE_MIDDLE), 0);
	fClusterList->AddColumn(new BIntegerColumn("Ping", 50, 40, 100,
		B_ALIGN_RIGHT), 1);
	fClusterList->AddColumn(new BIntegerColumn("Score", 60, 50, 140,
		B_ALIGN_RIGHT), 2);
	fClusterList->SetSortingEnabled(true);
	fClusterList->SetSortColumn(fClusterList->ColumnAt(1), false, true);
	// Single-click on a row updates the Server panel and arms the
	// Connect button; we use SelectionMessage so the user doesn't have
	// to double-click.
	fClusterList->SetSelectionMessage(new BMessage(kMsgClusterRowInvoked));
	fClusterList->SetTarget(this);

	BLayoutBuilder::Group<>(fClusterBox, B_VERTICAL, B_USE_SMALL_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING, B_USE_BIG_INSETS,
			B_USE_DEFAULT_SPACING, B_USE_DEFAULT_SPACING)
		.Add(fClusterList);
	fClusterBox->Hide();

	// --- status bar -----------------------------------------------------
	fStatusBar = new BStringView("statusBar",
		"Fetching server catalogue from vpngate.net" B_UTF8_ELLIPSIS);
	BFont small(be_plain_font);
	small.SetSize(small.Size() * 0.9f);
	fStatusBar->SetFont(&small);

	// --- toolbar --------------------------------------------------------
	// Mirrors the Map menu so the common gestures (zoom, fit, toggle
	// tiles, reload) are reachable without pulling the menu down. Labels
	// use the same Unicode symbols the system file/zoom dialogs use, so
	// they read at a glance without dragging a per-icon HVIF into the
	// build.
	BButton* zoomInButton = new BButton("tbZoomIn", "+",
		new BMessage(kMsgZoomIn));
	BButton* zoomOutButton = new BButton("tbZoomOut", "\xe2\x88\x92",
		new BMessage(kMsgZoomOut));
	BButton* fitButton = new BButton("tbFit", "Fit",
		new BMessage(kMsgZoomFit));
	BButton* tilesButton = new BButton("tbTiles", "Tiles",
		new BMessage(kMsgToggleTiles));
	BButton* refreshButton = new BButton("tbRefresh", "Refresh",
		new BMessage(kMsgRefresh));

	BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
		.Add(menuBar)
		.AddGroup(B_HORIZONTAL, B_USE_SMALL_SPACING)
			.SetInsets(B_USE_WINDOW_INSETS, B_USE_HALF_ITEM_SPACING,
				B_USE_WINDOW_INSETS, B_USE_HALF_ITEM_SPACING)
			.Add(zoomInButton)
			.Add(zoomOutButton)
			.Add(fitButton)
			.Add(tilesButton)
			.AddGlue()
			.Add(refreshButton)
		.End()
		.AddGroup(B_HORIZONTAL, B_USE_DEFAULT_SPACING)
			.SetInsets(B_USE_WINDOW_INSETS, B_USE_HALF_ITEM_SPACING,
				B_USE_WINDOW_INSETS, B_USE_HALF_ITEM_SPACING)
			.Add(fMap, 0.72f)
			.AddGroup(B_VERTICAL, B_USE_DEFAULT_SPACING, 0.28f)
				.Add(detailsBox)
				// Cluster box and the trailing glue both have weight 1
				// so they split the leftover space when the cluster is
				// visible (roughly half each); when the cluster is
				// hidden it contributes nothing and the glue takes
				// everything, keeping Connect at the bottom.
				.Add(fClusterBox, 1.0f)
				.AddGlue()
				.Add(fConnectButton)
			.End()
		.End()
		.AddGroup(B_HORIZONTAL, 0)
			.SetInsets(B_USE_WINDOW_INSETS, 0,
				B_USE_WINDOW_INSETS, B_USE_HALF_ITEM_SPACING)
			.Add(fStatusBar)
			.AddGlue()
		.End();
}


void
VPNMapWindow::_EnsureDaemon()
{
	if (fServer.IsValid())
		return;

	if (be_roster->Launch(kServerSignature) != B_OK
			&& be_roster->Launch(kServerSignature) != B_ALREADY_RUNNING) {
		// The roster will keep trying; we'll resolve in the loop below.
	}
	for (int attempt = 0; attempt < 30; attempt++) {
		fServer = BMessenger(kServerSignature);
		if (fServer.IsValid())
			return;
		snooze(100000);
	}
}


void
VPNMapWindow::_RequestCatalogue(bool force)
{
	if (!fServer.IsValid()) {
		_EnsureDaemon();
		if (!fServer.IsValid()) {
			if (fStatusBar != NULL)
				fStatusBar->SetText(
					"Daemon not reachable. Start sotoportego_server.");
			return;
		}
	}

	BMessage req(kMsgRequestVPNGate);
	req.AddMessenger(kFieldClient, BMessenger(this));
	if (force)
		req.AddBool("force", true);
	fServer.SendMessage(&req);

	if (fStatusBar != NULL) {
		fStatusBar->SetText(force
			? "Refreshing server catalogue" B_UTF8_ELLIPSIS
			: "Fetching server catalogue from vpngate.net" B_UTF8_ELLIPSIS);
	}
}


void
VPNMapWindow::_ApplyCatalogue(BMessage* message)
{
	if (fMap == NULL || message == NULL)
		return;

	const char* error = NULL;
	message->FindString(kFieldError, &error);
	BMessage probe;
	bool anyServer = message->FindMessage(kFieldVPNGateServer, 0, &probe)
		== B_OK;
	if (error != NULL && !anyServer) {
		// Pure failure: no servers AND an error string. Tell the user.
		BString status("Catalogue fetch failed: ");
		status << error;
		if (fStatusBar != NULL)
			fStatusBar->SetText(status.String());
		return;
	}

	fMap->ClearServers();
	fOvpnByHost.clear();

	BMessage entry;
	int32 count = 0;
	for (int32 i = 0;
			message->FindMessage(kFieldVPNGateServer, i, &entry) == B_OK;
			i++) {
		ServerPin pin;
		const char* host = NULL;
		entry.FindString(kFieldVPNGateHost, &host);
		if (host == NULL || host[0] == '\0')
			continue;
		pin.host = host;

		const char* s = NULL;
		if (entry.FindString(kFieldVPNGateCountryShort, &s) == B_OK)
			pin.countryShort = s;
		if (entry.FindString(kFieldVPNGateCountryLong, &s) == B_OK)
			pin.countryLong = s;
		if (entry.FindString(kFieldVPNGateLogPolicy, &s) == B_OK)
			pin.logPolicy = s;

		entry.FindFloat(kFieldVPNGateLatitude, &pin.latitude);
		entry.FindFloat(kFieldVPNGateLongitude, &pin.longitude);
		entry.FindInt32(kFieldVPNGateScore, &pin.score);
		entry.FindInt32(kFieldVPNGatePing, &pin.pingMs);
		entry.FindInt32(kFieldVPNGateSpeedMbps, &pin.speedMbps);
		entry.FindInt32(kFieldVPNGateSessions, &pin.sessions);

		fMap->AddServer(pin);

		const char* ovpn = NULL;
		if (entry.FindString(kFieldVPNGateConfigBase64, &ovpn) == B_OK
				&& ovpn != NULL) {
			fOvpnByHost[pin.host] = ovpn;
		}
		count++;
	}

	// Defer the fit through the looper rather than calling ZoomToFit()
	// inline: when the daemon answers from cache the catalogue lands
	// during initial layout, with the map view's Bounds() still at zero,
	// and the resulting zoom is meaningless. Posting kMsgZoomFit lets the
	// layout settle first.
	PostMessage(kMsgZoomFit, fMap);
	_RefreshSidePanel();

	if (fStatusBar != NULL) {
		BString status;
		status << count << " server" << (count == 1 ? "" : "s")
			<< " loaded";
		if (error != NULL && error[0] != '\0')
			status << " (partial: " << error << ")";
		fStatusBar->SetText(status.String());
	}
}


void
VPNMapWindow::_BeginConnectFlow()
{
	const ServerPin* picked = fMap != NULL ? fMap->SelectedServer() : NULL;
	if (picked == NULL)
		return;

	BString prefilled("vpn");	// vpngate's documented anonymous credentials
	CredentialsWindow* prompt = new CredentialsWindow(this, BMessenger(this),
		kMsgCredentialsOK, kMsgCredentialsCancel,
		picked->host.String(), prefilled);
	prompt->Show();
}


void
VPNMapWindow::_SendConnectWith(const char* user, const char* pass)
{
	if (!fServer.IsValid())
		return;

	const ServerPin* picked = fMap != NULL ? fMap->SelectedServer() : NULL;
	if (picked == NULL)
		return;

	std::map<BString, BString>::const_iterator it
		= fOvpnByHost.find(picked->host);
	if (it == fOvpnByHost.end()) {
		BAlert* alert = new BAlert("noConfig",
			"This server has no .ovpn payload cached; refresh the catalogue.",
			"OK");
		alert->SetFlags(alert->Flags() | B_CLOSE_ON_ESCAPE);
		alert->Go(NULL);
		return;
	}

	BMessage connect(kMsgConnectVPNGate);
	connect.AddMessenger(kFieldClient, BMessenger(this));
	connect.AddString(kFieldVPNGateHost, picked->host);
	connect.AddString(kFieldVPNGateCountryLong, picked->countryLong);
	connect.AddString(kFieldVPNGateConfigBase64, it->second.String());
	if (user != NULL && user[0] != '\0')
		connect.AddString(kFieldUsername, user);
	if (pass != NULL && pass[0] != '\0')
		connect.AddString(kFieldPassword, pass);
	fServer.SendMessage(&connect);

	if (fStatusBar != NULL) {
		BString status("Connecting to ");
		status << picked->host;
		status << B_UTF8_ELLIPSIS;
		fStatusBar->SetText(status.String());
	}
}


void
VPNMapWindow::_RefreshSidePanel()
{
	const ServerPin* picked = fMap != NULL ? fMap->SelectedServer() : NULL;

	if (picked == NULL) {
		const char* dash = "\xe2\x80\x94";
		if (fHostValue != NULL)		fHostValue->SetText(dash);
		if (fCountryValue != NULL)	fCountryValue->SetText(dash);
		if (fPingValue != NULL)
			fPingValue->SetMetric("", MetricPill::kTierUnknown);
		if (fScoreValue != NULL)
			fScoreValue->SetMetric("", MetricPill::kTierUnknown);
		if (fSessionsValue != NULL)
			fSessionsValue->SetMetric("", MetricPill::kTierUnknown);
		if (fLogPolicyValue != NULL) fLogPolicyValue->SetText(dash);
		if (fConnectButton != NULL)	fConnectButton->SetEnabled(false);
		return;
	}

	if (fHostValue != NULL)
		fHostValue->SetText(picked->host.String());

	if (fCountryValue != NULL) {
		BString country(picked->countryLong);
		if (picked->countryShort.Length() > 0) {
			country << " (";
			country << picked->countryShort;
			country << ")";
		}
		fCountryValue->SetText(country.String());
	}

	char buf[64];
	if (fPingValue != NULL) {
		snprintf(buf, sizeof(buf), "%" B_PRId32 " ms", picked->pingMs);
		fPingValue->SetMetric(buf, MetricPill::TierForPing(picked->pingMs));
	}
	if (fScoreValue != NULL) {
		snprintf(buf, sizeof(buf), "%" B_PRId32, picked->score);
		fScoreValue->SetMetric(buf, MetricPill::TierForScore(picked->score));
	}
	if (fSessionsValue != NULL) {
		snprintf(buf, sizeof(buf), "%" B_PRId32, picked->sessions);
		fSessionsValue->SetMetric(buf,
			MetricPill::TierForSessions(picked->sessions));
	}
	if (fLogPolicyValue != NULL) {
		fLogPolicyValue->SetText(picked->logPolicy.Length() > 0
			? picked->logPolicy.String() : "\xe2\x80\x94");
	}

	if (fConnectButton != NULL)
		fConnectButton->SetEnabled(true);
}


void
VPNMapWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgServerSelected:
			// MapView re-posts the click as kMsgServerSelected with the
			// host string; the side panel reads through
			// MapView::SelectedServer() which has been updated already.
			_RefreshSidePanel();
			// A single-pin click invalidates whatever cluster drill-down
			// was on screen: the user has clearly moved on.
			_HideCluster();
			break;

		case kMsgClusterSelected:
			// MapView fires this alongside kMsgServerSelected when the
			// click landed on a cluster (count > 1). Populate the
			// drill-down list with every member; the Server panel above
			// stays on the cluster's representative until the user
			// picks a different row.
			_ApplyCluster(message);
			break;

		case kMsgClusterRowInvoked:
			_PickClusterRow();
			break;

		case kMsgZoomIn:
		case kMsgZoomOut:
		case kMsgZoomFit:
		case kMsgToggleTiles:
			if (fMap != NULL)
				fMap->MessageReceived(message);
			break;

		case kMsgRefresh:
			_RequestCatalogue(true);
			break;

		case kMsgVPNGateList:
			_ApplyCatalogue(message);
			break;

		case kMsgStatusUpdate:
		{
			if (fMap == NULL)
				break;
			// Self pin: only update once both lat and lon arrive (the
			// daemon omits them on lookup failure rather than sending
			// zeroes, so a missing field means "still don't know").
			float lat = 0.0f, lon = 0.0f;
			if (message->FindFloat(kFieldHomeLat, &lat) == B_OK
					&& message->FindFloat(kFieldHomeLon, &lon) == B_OK) {
				const char* country = NULL;
				message->FindString(kFieldHomeCountry, &country);
				fMap->SetSelfPosition(lat, lon,
					country != NULL ? country : "You are here");
			}
			// Connection arc: gate on the actual VPN state, not just the
			// presence of kFieldConnectedHost. The daemon clears the host
			// on disconnect, but defending in the GUI keeps the arc from
			// ever pointing at a previous session if a status broadcast
			// somewhere up the chain forgets to drop the field.
			int32 stateValue = (int32)VPN_STATE_DISCONNECTED;
			message->FindInt32(kFieldState, &stateValue);
			VPNState state = (VPNState)stateValue;
			bool isLive = state != VPN_STATE_DISCONNECTED
				&& state != VPN_STATE_ERROR;

			const char* connectedHost = NULL;
			if (isLive
					&& message->FindString(kFieldConnectedHost,
						&connectedHost) == B_OK
					&& connectedHost != NULL && connectedHost[0] != '\0') {
				fMap->SetActiveHost(BString(connectedHost));
			} else {
				fMap->SetActiveHost(BString(""));
			}
			break;
		}

		case kMsgConnectPicked:
			_BeginConnectFlow();
			break;

		case kMsgCredentialsOK:
		{
			const char* user = "";
			const char* pass = "";
			message->FindString(kFieldUsername, &user);
			message->FindString(kFieldPassword, &pass);
			_SendConnectWith(user, pass);
			break;
		}
		case kMsgCredentialsCancel:
			// User backed out; leave the side panel alone.
			break;

		default:
			BWindow::MessageReceived(message);
			break;
	}
}


void
VPNMapWindow::_ApplyCluster(const BMessage* message)
{
	if (fClusterList == NULL || fClusterBox == NULL)
		return;

	fClusterList->Clear();

	int32 count = 0;
	for (;; count++) {
		const char* host = NULL;
		if (message->FindString(kClusterHost, count, &host) != B_OK
				|| host == NULL || host[0] == '\0') {
			break;
		}

		int32 ping = 0;
		int32 score = 0;
		message->FindInt32(kClusterPing, count, &ping);
		message->FindInt32(kClusterScore, count, &score);

		BRow* row = new BRow();
		row->SetField(new BStringField(host), 0);
		row->SetField(new BIntegerField(ping), 1);
		row->SetField(new BIntegerField(score), 2);
		fClusterList->AddRow(row);
	}

	if (count == 0) {
		_HideCluster();
		return;
	}

	BString label("Servers in this area (");
	label << count << ")";
	fClusterBox->SetLabel(label.String());

	if (fClusterBox->IsHidden())
		fClusterBox->Show();
}


void
VPNMapWindow::_PickClusterRow()
{
	if (fClusterList == NULL || fMap == NULL)
		return;

	BRow* row = fClusterList->CurrentSelection();
	if (row == NULL)
		return;

	BStringField* hostField = dynamic_cast<BStringField*>(row->GetField(0));
	if (hostField == NULL)
		return;

	// Promote the picked host to the map's live selection so the Server
	// panel above shows its details and the existing Connect button
	// works without any extra wiring. SetSelectedHost is a no-op if the
	// host isn't in the catalogue, which can't happen here since the
	// cluster came from the same catalogue.
	fMap->SetSelectedHost(BString(hostField->String()));
	_RefreshSidePanel();
}


void
VPNMapWindow::_HideCluster()
{
	if (fClusterList != NULL)
		fClusterList->Clear();
	if (fClusterBox != NULL && !fClusterBox->IsHidden())
		fClusterBox->Hide();
}
