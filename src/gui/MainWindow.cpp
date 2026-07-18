/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "MainWindow.h"

#include <stdio.h>
#include <time.h>

#include <Alert.h>
#include <Application.h>
#include <Box.h>
#include <Button.h>
#include <Entry.h>
#include <FilePanel.h>
#include <Font.h>
#include <MessageRunner.h>
#include <GroupLayout.h>
#include <Key.h>
#include <KeyStore.h>
#include <LayoutBuilder.h>
#include <ListItem.h>
#include <ListView.h>
#include <Menu.h>
#include <MenuBar.h>
#include <MenuItem.h>
#include <Message.h>
#include <OS.h>
#include <Path.h>
#include <Roster.h>
#include <ScrollView.h>
#include <StringView.h>
#include <TabView.h>
#include <View.h>

#include "CredentialsWindow.h"
#include "DeskbarIcon.h"
#include "HeaderView.h"
#include "OpenVPNConfigParser.h"
#include "WireGuardConfigParser.h"
#include "VPNMapWindow.h"
#include "VPNProfile.h"
#include "VPNProtocol.h"
#include "VPNStats.h"
#include "VaporettoWindow.h"


// GUI-private message codes.
static const uint32 kMsgPrimaryAction		= 'gAct';
static const uint32 kMsgConnectAction		= 'gCon';
static const uint32 kMsgDisconnectAction	= 'gDis';
static const uint32 kMsgAddProfile			= 'gAdd';
static const uint32 kMsgRemoveProfile		= 'gRem';
static const uint32 kMsgProfileSelected		= 'gSel';
static const uint32 kMsgImportRefs			= 'gImp';
static const uint32 kMsgCredentialsOK		= 'gCrO';
static const uint32 kMsgCredentialsCancel	= 'gCrC';
static const uint32 kMsgVaporetto			= 'gVap';
static const uint32 kMsgForgetPassword		= 'gFor';
static const uint32 kMsgInstallDeskbar		= 'gDIn';
static const uint32 kMsgRemoveDeskbar		= 'gDRm';
static const uint32 kMsgBrowseOnMap			= 'gMap';
static const uint32 kMsgUptimeTick			= 'gUpT';

static const char* const kBackendName	= "OpenVPN";


// BKeyStore helpers (defined at the bottom of the file).
static bool		load_stored_credentials(const char* profileName,
					BString& outUser, BString& outPass);
static void		save_credentials(const char* profileName, const char* user,
					const char* password);
static void		forget_credentials(const char* profileName);


MainWindow::MainWindow()
	:
	BWindow(BRect(100, 100, 720, 560), "Sotoportego", B_TITLED_WINDOW,
		B_AUTO_UPDATE_SIZE_LIMITS | B_QUIT_ON_WINDOW_CLOSE),
	fServer(),
	fState(VPN_STATE_DISCONNECTED),
	fHeader(NULL),
	fServerLabel(NULL),
	fBackendLabel(NULL),
	fProtocolLabel(NULL),
	fTunnelIPValue(NULL),
	fExternalIPValue(NULL),
	fSinceValue(NULL),
	fDownValue(NULL),
	fUpValue(NULL),
	fProfileList(NULL),
	fEventLog(NULL),
	fAddButton(NULL),
	fRemoveButton(NULL),
	fActionButton(NULL),
	fStatusBar(NULL),
	fConnectedSince(0),
	fUptimeTimer(NULL),
	fImportPanel(NULL),
	fProfiles(),
	fSelectedName(),
	fCountry(),
	fLastConnectProfile(),
	fLastUsedStoredCredentials(false)
{
	_BuildLayout();
	_UpdateForState(VPN_STATE_DISCONNECTED, NULL);
	_RefreshDetails();
	_EnsureSubscribed();
}


MainWindow::~MainWindow()
{
	_StopUptimeTimer();
	delete fImportPanel;
}


void
MainWindow::_BuildLayout()
{
	BMenuBar* menuBar = new BMenuBar("menubar");

	BMenu* appMenu = new BMenu("App");
	appMenu->AddItem(new BMenuItem("About Sotoportego" B_UTF8_ELLIPSIS,
		new BMessage(B_ABOUT_REQUESTED)));
	appMenu->AddSeparatorItem();
	appMenu->AddItem(new BMenuItem("Quit", new BMessage(B_QUIT_REQUESTED), 'Q'));
	menuBar->AddItem(appMenu);

	BMenu* connectionMenu = new BMenu("Connection");
	connectionMenu->AddItem(new BMenuItem("Connect",
		new BMessage(kMsgConnectAction)));
	connectionMenu->AddItem(new BMenuItem("Disconnect",
		new BMessage(kMsgDisconnectAction)));
	connectionMenu->AddSeparatorItem();
	connectionMenu->AddItem(new BMenuItem("Forget saved password",
		new BMessage(kMsgForgetPassword)));
	menuBar->AddItem(connectionMenu);

	BMenu* toolsMenu = new BMenu("Tools");
	toolsMenu->AddItem(new BMenuItem("Browse servers on map" B_UTF8_ELLIPSIS,
		new BMessage(kMsgBrowseOnMap)));
	toolsMenu->AddSeparatorItem();
	toolsMenu->AddItem(new BMenuItem("Install Deskbar icon",
		new BMessage(kMsgInstallDeskbar)));
	toolsMenu->AddItem(new BMenuItem("Remove Deskbar icon",
		new BMessage(kMsgRemoveDeskbar)));
	menuBar->AddItem(toolsMenu);

	fHeader = new HeaderView("header");
	fHeader->SetEasterEggTarget(BMessenger(this), kMsgVaporetto);

	BTabView* tabs = new BTabView("tabs", B_WIDTH_FROM_LABEL);
	tabs->AddTab(_BuildConnectionTab());
	tabs->AddTab(_BuildStatisticsTab());
	tabs->TabAt(0)->SetLabel("Connection");
	tabs->TabAt(1)->SetLabel("Statistics");

	fStatusBar = new BStringView("statusBar", "Disconnected");
	BFont smallFont(be_plain_font);
	smallFont.SetSize(smallFont.Size() * 0.9f);
	fStatusBar->SetFont(&smallFont);

	BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
		.Add(menuBar)
		.Add(fHeader)
		.AddGroup(B_VERTICAL, B_USE_DEFAULT_SPACING)
			.SetInsets(B_USE_WINDOW_INSETS, B_USE_HALF_ITEM_SPACING,
				B_USE_WINDOW_INSETS, B_USE_HALF_ITEM_SPACING)
			.Add(tabs)
		.End()
		.AddGroup(B_HORIZONTAL, 0)
			.SetInsets(B_USE_WINDOW_INSETS, 0,
				B_USE_WINDOW_INSETS, B_USE_HALF_ITEM_SPACING)
			.Add(fStatusBar)
			.AddGlue()
		.End();
}


BView*
MainWindow::_BuildConnectionTab()
{
	BView* tab = new BView("connectionTab", B_WILL_DRAW);
	tab->SetViewUIColor(B_PANEL_BACKGROUND_COLOR);

	// --- Left column: profile list -----------------------------------------
	BBox* profilesBox = new BBox("profilesBox");
	profilesBox->SetLabel("Profiles");

	fProfileList = new BListView("profileList");
	fProfileList->SetSelectionMessage(new BMessage(kMsgProfileSelected));
	fProfileList->SetInvocationMessage(new BMessage(kMsgPrimaryAction));
	BScrollView* listScroll = new BScrollView("profileScroll", fProfileList,
		0, false, true);

	fAddButton = new BButton("addProfile", "+",
		new BMessage(kMsgAddProfile));
	fRemoveButton = new BButton("removeProfile", "\xe2\x80\x93",
		new BMessage(kMsgRemoveProfile));
	fRemoveButton->SetEnabled(false);

	BLayoutBuilder::Group<>(profilesBox, B_VERTICAL, B_USE_SMALL_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING, B_USE_BIG_INSETS,
			B_USE_DEFAULT_SPACING, B_USE_DEFAULT_SPACING)
		.Add(listScroll)
		.AddGroup(B_HORIZONTAL, B_USE_SMALL_SPACING)
			.Add(fAddButton)
			.Add(fRemoveButton)
			.AddGlue()
		.End();

	// --- Right column: server details + action -----------------------------
	BBox* detailsBox = new BBox("detailsBox");
	detailsBox->SetLabel("Server");

	// Captions stay regular weight; values are bold so the eye lands on the
	// data, not on the labels. Laid out as a two-column grid so each value
	// sits on the same baseline as its caption.
	fServerLabel = new BStringView("serverLabel", "\xe2\x80\x94");
	fServerLabel->SetFont(be_bold_font);
	fBackendLabel = new BStringView("backendLabel", kBackendName);
	fBackendLabel->SetFont(be_bold_font);
	fProtocolLabel = new BStringView("protocolLabel", "\xe2\x80\x94");
	fProtocolLabel->SetFont(be_bold_font);
	fTunnelIPValue = new BStringView("tunnelIPValue", "\xe2\x80\x94");
	fTunnelIPValue->SetFont(be_bold_font);
	fExternalIPValue = new BStringView("externalIPValue", "\xe2\x80\x94");
	fExternalIPValue->SetFont(be_bold_font);

	BLayoutBuilder::Grid<>(detailsBox, B_USE_DEFAULT_SPACING,
			B_USE_SMALL_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING, B_USE_BIG_INSETS,
			B_USE_DEFAULT_SPACING, B_USE_DEFAULT_SPACING)
		.Add(new BStringView("hostCaption", "Host:"), 0, 0)
		.Add(fServerLabel, 1, 0)
		.Add(new BStringView("backendCaption", "Backend:"), 0, 1)
		.Add(fBackendLabel, 1, 1)
		.Add(new BStringView("protocolCaption", "Protocol:"), 0, 2)
		.Add(fProtocolLabel, 1, 2)
		.Add(new BStringView("tunnelIPCaption", "Tunnel IP:"), 0, 3)
		.Add(fTunnelIPValue, 1, 3)
		.Add(new BStringView("externalIPCaption", "External IP:"), 0, 4)
		.Add(fExternalIPValue, 1, 4);

	fActionButton = new BButton("actionButton", "Connect",
		new BMessage(kMsgPrimaryAction));
	fActionButton->MakeDefault(true);
	fActionButton->SetEnabled(false);

	BLayoutBuilder::Group<>(tab, B_VERTICAL, B_USE_DEFAULT_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING)
		.AddGroup(B_HORIZONTAL, B_USE_DEFAULT_SPACING)
			.Add(profilesBox, 0.40f)
			.Add(detailsBox, 0.60f)
		.End()
		.AddGroup(B_HORIZONTAL, 0)
			.AddGlue()
			.Add(fActionButton)
		.End();

	return tab;
}


BView*
MainWindow::_BuildStatisticsTab()
{
	BView* tab = new BView("statisticsTab", B_WILL_DRAW);
	tab->SetViewUIColor(B_PANEL_BACKGROUND_COLOR);

	// --- Session summary (left) --------------------------------------------
	BBox* sessionBox = new BBox("sessionBox");
	sessionBox->SetLabel("Session");

	fSinceValue = new BStringView("sinceValue", "\xe2\x80\x94");
	fDownValue = new BStringView("downValue", "0 B");
	fUpValue = new BStringView("upValue", "0 B");

	BFont monoFont(be_fixed_font);
	fSinceValue->SetFont(&monoFont);
	fDownValue->SetFont(&monoFont);
	fUpValue->SetFont(&monoFont);

	BLayoutBuilder::Grid<>(sessionBox, B_USE_DEFAULT_SPACING,
			B_USE_SMALL_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING, B_USE_BIG_INSETS,
			B_USE_DEFAULT_SPACING, B_USE_DEFAULT_SPACING)
		.Add(new BStringView("sinceLabel", "Since"), 0, 0)
		.Add(fSinceValue, 1, 0)
		.Add(new BStringView("downLabel", "Download"), 0, 1)
		.Add(fDownValue, 1, 1)
		.Add(new BStringView("upLabel", "Upload"), 0, 2)
		.Add(fUpValue, 1, 2);

	// --- Event log (right) -------------------------------------------------
	BBox* eventsBox = new BBox("eventsBox");
	eventsBox->SetLabel("Events");

	fEventLog = new BListView("eventLog");
	fEventLog->SetFont(&monoFont);
	BScrollView* eventScroll = new BScrollView("eventScroll", fEventLog,
		0, false, true);

	BLayoutBuilder::Group<>(eventsBox, B_VERTICAL, B_USE_SMALL_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING, B_USE_BIG_INSETS,
			B_USE_DEFAULT_SPACING, B_USE_DEFAULT_SPACING)
		.Add(eventScroll);

	BLayoutBuilder::Group<>(tab, B_HORIZONTAL, B_USE_DEFAULT_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING)
		.Add(sessionBox, 0.40f)
		.Add(eventsBox, 0.60f);

	return tab;
}


void
MainWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgPrimaryAction:
			// The primary button means connect when idle, disconnect otherwise.
			if (fState == VPN_STATE_DISCONNECTED || fState == VPN_STATE_ERROR)
				_BeginConnectFlow();
			else
				_SendDisconnect();
			break;

		case kMsgConnectAction:
			_BeginConnectFlow();
			break;
		case kMsgDisconnectAction:
			_SendDisconnect();
			break;

		case kMsgCredentialsOK:
		{
			const char* user = "";
			const char* pass = "";
			bool remember = false;
			message->FindString(kFieldUsername, &user);
			message->FindString(kFieldPassword, &pass);
			message->FindBool(kFieldRemember, &remember);
			if (remember && pass != NULL && *pass != '\0') {
				const VPNProfile* sel = _SelectedProfile();
				if (sel != NULL) {
					save_credentials(sel->fName.String(),
						user != NULL ? user : "", pass);
				}
			}
			_SendConnectWith(user, pass);
			break;
		}
		case kMsgCredentialsCancel:
			// User dismissed the dialog; nothing to do, the connect attempt
			// was never sent.
			break;

		case kMsgVaporetto:
		{
			// The HeaderView fires this after the user taps the logo seven
			// times in a row. Open a vaporetto window once per trigger;
			// dismissing it closes for free thanks to B_QUIT_ON_WINDOW_CLOSE.
			VaporettoWindow* vw = new VaporettoWindow();
			vw->Show();
			break;
		}

		case kMsgAddProfile:
			_OpenImportPanel();
			break;
		case kMsgRemoveProfile:
			_DeleteSelectedProfile();
			break;
		case kMsgForgetPassword:
			_ForgetSelectedPassword();
			break;
		case kMsgInstallDeskbar:
			_InstallDeskbarIcon();
			break;
		case kMsgRemoveDeskbar:
			_RemoveDeskbarIcon();
			break;
		case kMsgBrowseOnMap:
		{
			// Open the map browser. B_QUIT_ON_WINDOW_CLOSE in the window's
			// flags means closing it just disposes of the BWindow; opening
			// it again from the menu spawns a fresh one. Multiple
			// instances are harmless because the catalogue is static for
			// now (will become a daemon-broadcast list later).
			VPNMapWindow* window = new VPNMapWindow();
			window->Show();
			break;
		}
		case kMsgProfileSelected:
		{
			int32 index = fProfileList->CurrentSelection();
			fSelectedName = "";
			if (index >= 0 && (size_t)index < fProfiles.size())
				fSelectedName = fProfiles[index].fName;
			_RefreshDetails();
			break;
		}
		case kMsgImportRefs:
		{
			entry_ref ref;
			for (int32 i = 0; message->FindRef("refs", i, &ref) == B_OK; i++)
				_ImportFile(ref);
			break;
		}

		case kMsgListProfiles:
			_ApplyProfileList(message);
			break;

		case B_ABOUT_REQUESTED:
			be_app->PostMessage(B_ABOUT_REQUESTED);
			break;

		case kMsgStatusUpdate:
		{
			int32 state = VPN_STATE_DISCONNECTED;
			message->FindInt32(kFieldState, &state);
			const char* detail = NULL;
			if (message->FindString(kFieldDetail, &detail) != B_OK)
				detail = NULL;
			const char* localIP = NULL;
			if (message->FindString(kFieldLocalIP, &localIP) == B_OK
					&& localIP != NULL && fTunnelIPValue != NULL) {
				fTunnelIPValue->SetText(localIP[0] != '\0'
					? localIP : "\xe2\x80\x94");
			} else if (fTunnelIPValue != NULL
					&& (VPNState)state == VPN_STATE_DISCONNECTED) {
				fTunnelIPValue->SetText("\xe2\x80\x94");
			}
			// External (public) IP arrives later, after the geo-lookup
			// finishes -- it's the IP the outside world sees, not the
			// in-tunnel address above. Clear it back to dash on
			// disconnect so a previous session's value doesn't linger.
			const char* externalIP = NULL;
			if (message->FindString(kFieldExternalIP, &externalIP) == B_OK
					&& externalIP != NULL && fExternalIPValue != NULL) {
				fExternalIPValue->SetText(externalIP[0] != '\0'
					? externalIP : "\xe2\x80\x94");
			} else if (fExternalIPValue != NULL
					&& (VPNState)state == VPN_STATE_DISCONNECTED) {
				fExternalIPValue->SetText("\xe2\x80\x94");
			}
			// Country either arrives in this update (the daemon broadcasts
			// it after the geo-lookup finishes) or gets cleared when the
			// session ends.
			const char* country = NULL;
			if (message->FindString(kFieldCountry, &country) == B_OK
					&& country != NULL && *country != '\0') {
				fCountry = country;
			} else if ((VPNState)state == VPN_STATE_DISCONNECTED
					|| (VPNState)state == VPN_STATE_ERROR) {
				fCountry = "";
			}
			_UpdateForState((VPNState)state, detail);
			_ApplyStats(message);
			break;
		}

		case kMsgStatsUpdate:
			_ApplyStats(message);
			break;

		case kMsgUptimeTick:
			// Cheap once-a-second refresh while the tunnel is up. The
			// state hasn't changed so the only field that visibly moves
			// is the elapsed-time suffix on the status bar.
			_RefreshStatusBar();
			break;

		default:
			BWindow::MessageReceived(message);
			break;
	}
}


void
MainWindow::_EnsureSubscribed()
{
	// Launch the daemon if needed, then subscribe and pull the current status.
	if (be_roster->Launch(kServerSignature) != B_OK
			&& be_roster->Launch(kServerSignature) != B_ALREADY_RUNNING) {
		// Best effort; the messenger check below decides whether we proceed.
	}

	for (int attempt = 0; attempt < 30; attempt++) {
		fServer = BMessenger(kServerSignature);
		if (fServer.IsValid())
			break;
		snooze(100000);
	}

	if (!fServer.IsValid()) {
		// The previous code silently disabled the Connect button and left
		// the user wondering why nothing worked. Tell them explicitly the
		// daemon isn't reachable -- usually because sotoportego_server is
		// not installed in PATH or its application signature can't be
		// resolved.
		_AppendEvent("Error \xe2\x80\x94 Sotoportego daemon not reachable");
		BAlert* alert = new BAlert("daemonOffline",
			"Could not reach the Sotoportego daemon.\n\n"
			"Make sure sotoportego_server is on PATH and its application "
			"signature is registered, then restart Sotoportego.",
			"OK", NULL, NULL, B_WIDTH_AS_USUAL, B_STOP_ALERT);
		alert->SetFlags(alert->Flags() | B_CLOSE_ON_ESCAPE);
		alert->Go(NULL);
		return;
	}

	BMessage subscribe(kMsgSubscribe);
	subscribe.AddMessenger(kFieldClient, BMessenger(this));
	fServer.SendMessage(&subscribe);

	BMessage status(kMsgGetStatus);
	status.AddMessenger(kFieldClient, BMessenger(this));
	fServer.SendMessage(&status);
}


void
MainWindow::_BeginConnectFlow()
{
	if (!fServer.IsValid())
		return;

	const VPNProfile* selected = _SelectedProfile();
	if (selected == NULL) {
		BAlert* alert = new BAlert("noProfile",
			"Pick or import a profile first.", "OK");
		alert->SetFlags(alert->Flags() | B_CLOSE_ON_ESCAPE);
		alert->Go();
		return;
	}

	// If the user previously asked us to remember this profile's password,
	// skip the dialog and go straight to Connect. The keystore returns
	// B_ERROR (and may prompt to unlock its keyring) on first access per
	// session; either way an empty result drops through to the prompt.
	BString storedUser;
	BString storedPass;
	if (load_stored_credentials(selected->fName.String(), storedUser,
			storedPass)) {
		fLastUsedStoredCredentials = true;
		_SendConnectWith(storedUser.String(), storedPass.String());
		return;
	}
	// The dialog path will set fLastUsedStoredCredentials = false in
	// _SendConnectWith via the kMsgCredentialsOK branch.
	fLastUsedStoredCredentials = false;

	// Always prompt otherwise -- we can't reliably know up-front whether
	// the .ovpn file requires interactive auth, and an empty prompt is
	// cheap to dismiss for cert-only configs.
	CredentialsWindow* prompt = new CredentialsWindow(this, BMessenger(this),
		kMsgCredentialsOK, kMsgCredentialsCancel,
		selected->fName.String(), selected->fUsername);
	prompt->Show();
}


void
MainWindow::_SendConnectWith(const char* username, const char* password)
{
	if (!fServer.IsValid())
		return;
	const VPNProfile* selected = _SelectedProfile();
	if (selected == NULL)
		return;

	// Snapshot which profile we're trying to authenticate against, so
	// the auth-failure path knows which keystore entry to clear.
	fLastConnectProfile = selected->fName;

	BMessage archive;
	selected->Archive(&archive);

	BMessage connect(kMsgConnect);
	connect.AddMessenger(kFieldClient, BMessenger(this));
	connect.AddMessage(kFieldProfile, &archive);
	if (username != NULL && username[0] != '\0')
		connect.AddString(kFieldUsername, username);
	if (password != NULL && password[0] != '\0')
		connect.AddString(kFieldPassword, password);
	fServer.SendMessage(&connect);
}


void
MainWindow::_SendDisconnect()
{
	if (!fServer.IsValid())
		return;

	BMessage disconnect(kMsgDisconnect);
	disconnect.AddMessenger(kFieldClient, BMessenger(this));
	fServer.SendMessage(&disconnect);
}


void
MainWindow::_UpdateForState(VPNState state, const char* detail)
{
	VPNState previous = fState;
	fState = state;

	const char* action = (state == VPN_STATE_DISCONNECTED
		|| state == VPN_STATE_ERROR) ? "Connect" : "Disconnect";

	const VPNProfile* selected = _SelectedProfile();

	if (fHeader != NULL) {
		fHeader->SetState(state);

		BString subtitle(vpn_state_name(state));
		if (detail != NULL && detail[0] != '\0') {
			subtitle << " \xc2\xb7 ";
			subtitle << detail;
		} else if (state != VPN_STATE_DISCONNECTED && selected != NULL) {
			char serverBuf[128];
			snprintf(serverBuf, sizeof(serverBuf), "%s:%u",
				selected->fServer.String(), (unsigned)selected->fPort);
			subtitle << " \xc2\xb7 ";
			subtitle << serverBuf;
		}
		fHeader->SetSubtitle(subtitle.String());
	}

	if (fActionButton != NULL) {
		fActionButton->SetLabel(action);
		bool canConnect = selected != NULL
			|| state == VPN_STATE_CONNECTING
			|| state == VPN_STATE_AUTHENTICATING
			|| state == VPN_STATE_CONNECTED
			|| state == VPN_STATE_RECONNECTING;
		fActionButton->SetEnabled(canConnect);
	}

	_RefreshStatusBar();

	// Drive the 1 Hz uptime tick only while the session is actually up:
	// any other state means there is no elapsed time to display.
	if (state == VPN_STATE_CONNECTED)
		_StartUptimeTimer();
	else
		_StopUptimeTimer();

	if (previous != state) {
		BString line(vpn_state_name(state));
		if (detail != NULL && detail[0] != '\0') {
			line << " \xe2\x80\x94 ";
			line << detail;
		}
		_AppendEvent(line.String());

		// Surface terminal errors front-and-centre: the slate header is
		// easy to glance past when openvpn fails after a couple of state
		// flips.
		if (state == VPN_STATE_ERROR && previous != VPN_STATE_ERROR) {
			// If we just used a stored password and the failure was an
			// auth rejection, drop the stored secret so the next Connect
			// prompts the user instead of looping on the same bad value.
			bool clearedStored = false;
			bool authFailed = (detail != NULL
				&& BString(detail).IFindFirst("authentication failed")
					>= 0);
			if (authFailed && fLastUsedStoredCredentials
					&& fLastConnectProfile.Length() > 0) {
				forget_credentials(fLastConnectProfile.String());
				clearedStored = true;
			}
			fLastUsedStoredCredentials = false;

			BString body("The VPN connection failed.");
			if (detail != NULL && detail[0] != '\0') {
				body << "\n\n";
				body << detail;
			}
			if (clearedStored) {
				body << "\n\nThe saved password has been cleared; you'll be "
					"asked for it on the next Connect.";
			}
			BAlert* alert = new BAlert("connectionError", body.String(),
				"OK", NULL, NULL, B_WIDTH_AS_USUAL, B_STOP_ALERT);
			alert->SetFlags(alert->Flags() | B_CLOSE_ON_ESCAPE);
			alert->Go(NULL);
		}
	}
}


void
MainWindow::_ApplyStats(const BMessage* message)
{
	VPNStats stats;
	stats.Unarchive(*message);

	if (fDownValue != NULL)
		fDownValue->SetText(_FormatBytes(stats.fBytesIn).String());
	if (fUpValue != NULL)
		fUpValue->SetText(_FormatBytes(stats.fBytesOut).String());

	// Cache the epoch the daemon recorded on CONNECTED so the status-bar
	// uptime tick has something to count from. _RefreshStatusBar picks
	// it up; this assignment is also what makes the very first
	// CONNECTED tick show 00:00:00 instead of a stale value from a
	// previous session.
	if (stats.fConnectedSince > 0)
		fConnectedSince = stats.fConnectedSince;

	if (fSinceValue != NULL) {
		if (stats.fConnectedSince > 0) {
			char buffer[32];
			struct tm local;
			time_t when = stats.fConnectedSince;
			localtime_r(&when, &local);
			strftime(buffer, sizeof(buffer), "%H:%M:%S", &local);
			fSinceValue->SetText(buffer);
		} else {
			fSinceValue->SetText("\xe2\x80\x94");
		}
	}
}


void
MainWindow::_AppendEvent(const char* text)
{
	if (fEventLog == NULL || text == NULL)
		return;

	char timeBuf[16];
	time_t now = time(NULL);
	struct tm local;
	localtime_r(&now, &local);
	strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", &local);

	BString line;
	line << timeBuf << "  " << text;
	fEventLog->AddItem(new BStringItem(line.String()));
	fEventLog->ScrollToSelection();

	int32 count = fEventLog->CountItems();
	if (count > 0)
		fEventLog->Select(count - 1);
}


void
MainWindow::_ApplyProfileList(const BMessage* message)
{
	fProfiles.clear();

	BMessage archive;
	for (int32 i = 0; message->FindMessage(kFieldProfile, i, &archive) == B_OK;
			i++) {
		VPNProfile profile;
		profile.Unarchive(archive);
		fProfiles.push_back(profile);
	}

	_RefreshProfileList();
	_RefreshDetails();
	_UpdateForState(fState, NULL);
}


void
MainWindow::_RefreshProfileList()
{
	if (fProfileList == NULL)
		return;

	// Remember the currently selected name so we can restore it after the
	// repopulate (the server's list may have arrived in a different order).
	if (fSelectedName.Length() == 0) {
		int32 index = fProfileList->CurrentSelection();
		if (index >= 0 && (size_t)index < fProfiles.size())
			fSelectedName = fProfiles[index].fName;
	}

	for (int32 i = fProfileList->CountItems() - 1; i >= 0; i--)
		delete fProfileList->RemoveItem(i);

	// First-run / empty-list onboarding: show a single disabled item that
	// hints at the next step, rather than an empty box that gives no clue
	// the "+" button does anything useful.
	if (fProfiles.empty()) {
		BStringItem* hint = new BStringItem(
			"No profiles \xe2\x80\x94 click + to import an .ovpn file.");
		hint->SetEnabled(false);
		fProfileList->AddItem(hint);
		fSelectedName = "";
		return;
	}

	int32 newSelection = -1;
	for (size_t i = 0; i < fProfiles.size(); i++) {
		fProfileList->AddItem(new BStringItem(fProfiles[i].fName.String()));
		if (fProfiles[i].fName == fSelectedName)
			newSelection = (int32)i;
	}

	if (newSelection < 0) {
		newSelection = 0;
		fSelectedName = fProfiles[0].fName;
	}

	fProfileList->Select(newSelection);
}


void
MainWindow::_RefreshDetails()
{
	const VPNProfile* selected = _SelectedProfile();
	bool hasSelection = selected != NULL;

	if (fRemoveButton != NULL)
		fRemoveButton->SetEnabled(hasSelection);

	if (fServerLabel != NULL) {
		if (hasSelection) {
			char buf[128];
			snprintf(buf, sizeof(buf), "%s:%u",
				selected->fServer.String(), (unsigned)selected->fPort);
			fServerLabel->SetText(buf);
		} else {
			fServerLabel->SetText("\xe2\x80\x94");
		}
	}

	if (fProtocolLabel != NULL) {
		fProtocolLabel->SetText(hasSelection
			? selected->fProtocol.String() : "\xe2\x80\x94");
	}

	if (fBackendLabel != NULL) {
		const char* backend = "\xe2\x80\x94";
		if (hasSelection) {
			backend = selected->fBackendType == VPN_BACKEND_WIREGUARD
				? "WireGuard"
				: selected->fBackendType == VPN_BACKEND_IPSEC
					? "IPSec" : "OpenVPN";
		}
		fBackendLabel->SetText(backend);
	}

	if (fActionButton != NULL) {
		bool isBusy = fState == VPN_STATE_CONNECTING
			|| fState == VPN_STATE_AUTHENTICATING
			|| fState == VPN_STATE_CONNECTED
			|| fState == VPN_STATE_RECONNECTING;
		fActionButton->SetEnabled(hasSelection || isBusy);
	}
}


void
MainWindow::_OpenImportPanel()
{
	if (fImportPanel == NULL) {
		BMessenger target(this);
		BMessage refsMessage(kMsgImportRefs);
		fImportPanel = new BFilePanel(B_OPEN_PANEL, &target, NULL,
			B_FILE_NODE, true, &refsMessage);
		fImportPanel->Window()->SetTitle("Import .ovpn profile");
	}
	fImportPanel->Show();
}


void
MainWindow::_ImportFile(const entry_ref& ref)
{
	if (!fServer.IsValid())
		return;

	BPath path(&ref);
	if (path.InitCheck() != B_OK)
		return;

	VPNProfile profile;

	// Sniff the file: a complete WireGuard .conf ([Interface] key + a [Peer]
	// with an Endpoint) is imported as WireGuard, otherwise we treat it as an
	// OpenVPN .ovpn. The daemon re-parses the file at connect time; here we
	// only fill the display fields.
	WireGuardConfig wg;
	if (WireGuardConfigParser::ParseFile(path.Path(), wg) && wg.IsComplete()) {
		profile.fBackendType = VPN_BACKEND_WIREGUARD;
		profile.fServer = wg.peer.endpointHost;
		profile.fPort = wg.peer.endpointPort;
		profile.fProtocol = "udp";
		profile.fConfigPath = path.Path();
		BString name(path.Leaf());
		if (name.IFindLast(".conf") == name.Length() - 5)
			name.Truncate(name.Length() - 5);
		profile.fName = name;
	} else {
		profile.fBackendType = VPN_BACKEND_OPENVPN;
		if (!OpenVPNConfigParser::ParseFile(path.Path(), profile)) {
			BAlert* alert = new BAlert("importFailed",
				"Could not read the selected config file.", "OK");
			alert->SetFlags(alert->Flags() | B_CLOSE_ON_ESCAPE);
			alert->Go();
			return;
		}
		if (profile.fServer.Length() == 0) {
			BAlert* alert = new BAlert("importWarning",
				"The .ovpn file has no 'remote' directive; the profile was "
				"saved but cannot be used until you fix the file.",
				"OK");
			alert->SetFlags(alert->Flags() | B_CLOSE_ON_ESCAPE);
			alert->Go();
		}
	}

	// Confirm before silently overwriting an existing profile that happens
	// to share a name with what we just parsed (vpngate filenames in
	// particular are very repetitive). The daemon's save path is keyed by
	// name and would otherwise blow away the previous server / config
	// without telling the user.
	for (size_t i = 0; i < fProfiles.size(); i++) {
		if (fProfiles[i].fName == profile.fName) {
			BString question;
			question << "A profile named '" << profile.fName
				<< "' already exists.\n\nReplace it with the file you just "
				   "imported?";
			BAlert* alert = new BAlert("overwriteProfile",
				question.String(), "Cancel", "Replace");
			alert->SetShortcut(0, B_ESCAPE);
			if (alert->Go() != 1)
				return;
			break;
		}
	}

	// Optimistically select the imported profile once the server echoes the
	// updated list back to us.
	fSelectedName = profile.fName;

	BMessage archive;
	profile.Archive(&archive);

	BMessage save(kMsgSaveProfile);
	save.AddMessenger(kFieldClient, BMessenger(this));
	save.AddMessage(kFieldProfile, &archive);
	fServer.SendMessage(&save);
}


void
MainWindow::_DeleteSelectedProfile()
{
	if (!fServer.IsValid())
		return;
	const VPNProfile* selected = _SelectedProfile();
	if (selected == NULL)
		return;

	BString question;
	question << "Delete profile '" << selected->fName << "'?";
	BAlert* alert = new BAlert("confirmDelete", question.String(),
		"Cancel", "Delete");
	alert->SetShortcut(0, B_ESCAPE);
	if (alert->Go() != 1)
		return;

	BMessage del(kMsgDeleteProfile);
	del.AddMessenger(kFieldClient, BMessenger(this));
	del.AddString(kFieldProfileName, selected->fName);
	fServer.SendMessage(&del);

	// Drop any stored password for this profile too: leaving a stale key
	// behind would resurface on a re-import with the same name.
	forget_credentials(selected->fName.String());

	fSelectedName = "";
}


void
MainWindow::_ForgetSelectedPassword()
{
	const VPNProfile* selected = _SelectedProfile();
	if (selected == NULL) {
		BAlert* alert = new BAlert("noProfile",
			"Pick a profile first.", "OK");
		alert->SetFlags(alert->Flags() | B_CLOSE_ON_ESCAPE);
		alert->Go();
		return;
	}

	// Confirm before clearing. It's a small, reversible action (the
	// user can retick Remember on the next Connect), but typing the
	// password again has a cost and we don't want a stray menu pick
	// to surprise them.
	BString question;
	question << "Forget the saved password for '" << selected->fName
		<< "'?\n\nYou'll be asked for it the next time you connect.";
	BAlert* confirm = new BAlert("confirmForget", question.String(),
		"Cancel", "Forget");
	confirm->SetShortcut(0, B_ESCAPE);
	if (confirm->Go() != 1)
		return;

	forget_credentials(selected->fName.String());

	BAlert* done = new BAlert("forgotten",
		"Done. The saved password (if any) has been cleared.", "OK");
	done->SetFlags(done->Flags() | B_CLOSE_ON_ESCAPE);
	done->Go();
}


// --- BKeyStore helpers ----------------------------------------------------
//
// We store one BPasswordKey per profile, keyed by profile name. The username
// rides on the SecondaryIdentifier slot, the password is the key's payload.
// Purpose is B_KEY_PURPOSE_NETWORK so the keystore browser groups them with
// other network credentials.

static bool
load_stored_credentials(const char* profileName, BString& outUser,
	BString& outPass)
{
	if (profileName == NULL || *profileName == '\0')
		return false;
	BKeyStore keystore;
	BPasswordKey key;
	if (keystore.GetKey(B_KEY_TYPE_PASSWORD, profileName, key) != B_OK)
		return false;
	outUser = key.SecondaryIdentifier();
	outPass = key.Password();
	return outPass.Length() > 0;
}


static void
save_credentials(const char* profileName, const char* user,
	const char* password)
{
	if (profileName == NULL || *profileName == '\0' || password == NULL)
		return;
	BKeyStore keystore;
	// AddKey refuses to overwrite, so drop any prior secret for this
	// profile before saving the new one.
	BPasswordKey existing;
	if (keystore.GetKey(B_KEY_TYPE_PASSWORD, profileName, existing) == B_OK)
		keystore.RemoveKey(existing);
	BPasswordKey key(password, B_KEY_PURPOSE_NETWORK, profileName,
		user != NULL ? user : "");
	keystore.AddKey(key);
}


static void
forget_credentials(const char* profileName)
{
	if (profileName == NULL || *profileName == '\0')
		return;
	BKeyStore keystore;
	BPasswordKey existing;
	if (keystore.GetKey(B_KEY_TYPE_PASSWORD, profileName, existing) == B_OK)
		keystore.RemoveKey(existing);
}


const VPNProfile*
MainWindow::_SelectedProfile() const
{
	if (fSelectedName.Length() == 0)
		return NULL;
	for (size_t i = 0; i < fProfiles.size(); i++) {
		if (fProfiles[i].fName == fSelectedName)
			return &fProfiles[i];
	}
	return NULL;
}


void
MainWindow::_InstallDeskbarIcon()
{
	if (DeskbarIcon::IsInDeskbar()) {
		BAlert* alert = new BAlert("deskbar",
			"The Sotoportego icon is already in your Deskbar.", "OK");
		alert->SetFlags(alert->Flags() | B_CLOSE_ON_ESCAPE);
		alert->Go(NULL);
		return;
	}
	status_t result = DeskbarIcon::AddToDeskbar();
	if (result != B_OK) {
		BString body("Could not install the Deskbar icon: ");
		body << strerror(result);
		body << "\n\nIs Deskbar running?";
		BAlert* alert = new BAlert("deskbarErr", body.String(), "OK",
			NULL, NULL, B_WIDTH_AS_USUAL, B_STOP_ALERT);
		alert->SetFlags(alert->Flags() | B_CLOSE_ON_ESCAPE);
		alert->Go(NULL);
	}
}


void
MainWindow::_RemoveDeskbarIcon()
{
	if (!DeskbarIcon::IsInDeskbar())
		return;
	DeskbarIcon::RemoveFromDeskbar();
}


void
MainWindow::_RefreshStatusBar()
{
	if (fStatusBar == NULL)
		return;
	BString status;
	status << (int32)fProfiles.size();
	status << (fProfiles.size() == 1 ? " profile \xc2\xb7 " : " profiles \xc2\xb7 ");
	status << vpn_state_name(fState);
	if (fState == VPN_STATE_CONNECTED) {
		if (fConnectedSince > 0) {
			time_t now = time(NULL);
			long elapsed = (long)(now - fConnectedSince);
			if (elapsed < 0)
				elapsed = 0;
			long hours = elapsed / 3600;
			long minutes = (elapsed % 3600) / 60;
			long seconds = elapsed % 60;
			char buf[32];
			if (hours > 0) {
				snprintf(buf, sizeof(buf), "%ld:%02ld:%02ld",
					hours, minutes, seconds);
			} else {
				snprintf(buf, sizeof(buf), "%02ld:%02ld",
					minutes, seconds);
			}
			status << " \xc2\xb7 ";
			status << buf;
		}
		if (fCountry.Length() > 0) {
			status << " \xc2\xb7 ";
			status << fCountry;
		}
	}
	fStatusBar->SetText(status.String());
}


void
MainWindow::_StartUptimeTimer()
{
	if (fUptimeTimer != NULL)
		return;
	BMessage tick(kMsgUptimeTick);
	fUptimeTimer = new BMessageRunner(BMessenger(this), &tick, 1000000);
	if (fUptimeTimer->InitCheck() != B_OK) {
		delete fUptimeTimer;
		fUptimeTimer = NULL;
	}
}


void
MainWindow::_StopUptimeTimer()
{
	delete fUptimeTimer;
	fUptimeTimer = NULL;
	// Drop the cached epoch so a future CONNECTED really shows 00:00
	// instead of inheriting the previous session's start time before
	// the first stats broadcast arrives.
	fConnectedSince = 0;
}


BString
MainWindow::_FormatBytes(int64 bytes)
{
	const char* units[] = { "B", "KB", "MB", "GB", "TB" };
	double value = (double)bytes;
	int unit = 0;
	while (value >= 1024.0 && unit < 4) {
		value /= 1024.0;
		unit++;
	}

	char buffer[48];
	if (unit == 0)
		snprintf(buffer, sizeof(buffer), "%lld B", (long long)bytes);
	else
		snprintf(buffer, sizeof(buffer), "%.1f %s", value, units[unit]);

	return BString(buffer);
}
