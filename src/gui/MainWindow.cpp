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
#include <Url.h>
#include <View.h>

#include "CredentialsWindow.h"
#include "DeskbarIcon.h"
#include "HeaderView.h"
#include "PeersWindow.h"
#include "TailscaleWindow.h"
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
static const uint32 kMsgAddTailscale		= 'gTsA';	// open the Tailscale dialog
static const uint32 kMsgTailscaleOK			= 'gTsO';	// dialog -> create profile
static const uint32 kMsgTailscaleSignup		= 'gTsS';	// open the account signup page
static const uint32 kMsgTailscaleAdmin		= 'gTsD';	// open the web admin console
static const uint32 kMsgShowPeers			= 'gTsP';	// open the peers window

// Where a new user goes to create a Tailscale account (opens in the browser).
// Tailscale has no email/password signup: an account is created by signing in
// with an identity provider (Google, Microsoft, GitHub, ...) the first time.
// This is the canonical start page; already-signed-in users get redirected to
// their admin console.
static const char* const kTailscaleSignupURL = "https://login.tailscale.com/start";
// The Tailscale web admin console (current domain: console.tailscale.com).
static const char* const kTailscaleAdminURL = "https://console.tailscale.com/admin";

static const char* const kBackendName	= "OpenVPN";


// Open a URL in the user's default browser. Uses BUrl's preferred-application
// path rather than be_roster->Launch("application/x-vnd.Be-URL.https", ...):
// the latter reports "Application could not be found" on stock Haiku because
// nothing is registered under that handler MIME, whereas BUrl resolves the
// https scheme correctly. Returns true on success.
static bool
open_url(const char* url)
{
	if (url == NULL || *url == '\0')
		return false;
	BUrl parsed(url, true);
	return parsed.OpenWithPreferredApplication(false) == B_OK;
}


// BKeyStore helpers (defined at the bottom of the file).
static bool		load_stored_credentials(const char* profileName,
					BString& outUser, BString& outPass);
static void		save_credentials(const char* profileName, const char* user,
					const char* password);
static void		forget_credentials(const char* profileName);
// Tailscale pre-auth key, stored as its own keystore entry (namespaced so it
// never collides with a profile's OpenVPN password).
static bool		load_authkey(const char* profileName, BString& outKey);
static void		save_authkey(const char* profileName, const char* authKey);
static void		forget_authkey(const char* profileName);


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
	fConnNotice(NULL),
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
	fLastUsedStoredCredentials(false),
	fHasConnectedProfile(false)
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

	BMenu* tailscaleMenu = new BMenu("Tailscale");
	tailscaleMenu->AddItem(new BMenuItem("Add Tailscale network" B_UTF8_ELLIPSIS,
		new BMessage(kMsgAddTailscale)));
	tailscaleMenu->AddItem(new BMenuItem("Show peers" B_UTF8_ELLIPSIS,
		new BMessage(kMsgShowPeers)));
	tailscaleMenu->AddSeparatorItem();
	tailscaleMenu->AddItem(new BMenuItem("Create a Tailscale account"
		B_UTF8_ELLIPSIS, new BMessage(kMsgTailscaleSignup)));
	tailscaleMenu->AddItem(new BMenuItem("Open admin console"
		B_UTF8_ELLIPSIS, new BMessage(kMsgTailscaleAdmin)));
	menuBar->AddItem(tailscaleMenu);

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

	// The primary action lives in the header banner, right-aligned.
	fActionButton = new BButton("actionButton", "Connect",
		new BMessage(kMsgPrimaryAction));
	fActionButton->MakeDefault(true);
	fActionButton->SetEnabled(false);
	fHeader->SetActionButton(fActionButton);

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

	// Shown only when the profile selected in the list isn't the one actually
	// connected, so the details above are never silently misread.
	fConnNotice = new BStringView("connNotice", "");
	BFont noticeFont(be_plain_font);
	noticeFont.SetSize(be_plain_font->Size() - 1);
	fConnNotice->SetFont(&noticeFont);
	fConnNotice->SetHighColor(tint_color(ui_color(B_PANEL_TEXT_COLOR), 0.65f));
	// Don't let the notice widen the window: a small min width plus end
	// truncation keep it inside whatever width the details already need.
	fConnNotice->SetExplicitMinSize(BSize(40, B_SIZE_UNSET));
	fConnNotice->SetTruncation(B_TRUNCATE_END);

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
		.Add(fExternalIPValue, 1, 4)
		.Add(fConnNotice, 0, 5, 2, 1);

	// The primary Connect/Disconnect button lives in the header banner
	// (see _BuildLayout), not at the bottom of this tab.
	BLayoutBuilder::Group<>(tab, B_VERTICAL, B_USE_DEFAULT_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING)
		.AddGroup(B_HORIZONTAL, B_USE_DEFAULT_SPACING)
			.Add(profilesBox, 0.40f)
			.Add(detailsBox, 0.60f)
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
		case kMsgAddTailscale:
		{
			// Collect a name + control server, then create a Tailscale profile.
			TailscaleWindow* dialog = new TailscaleWindow(this,
				BMessenger(this), kMsgTailscaleOK);
			dialog->Show();
			break;
		}
		case kMsgTailscaleOK:
		{
			const char* name = NULL;
			const char* url = NULL;
			const char* authKey = NULL;
			if (message->FindString(kFieldTsName, &name) != B_OK
					|| name == NULL || *name == '\0')
				break;
			if (message->FindString(kFieldTsUrl, &url) != B_OK || url == NULL)
				url = "controlplane.tailscale.com";
			if (message->FindString(kFieldTsAuthKey, &authKey) != B_OK)
				authKey = "";
			_CreateTailscaleProfile(name, url, authKey);
			break;
		}
		case kMsgTailscaleSignup:
			// Open the Tailscale signup page in the default web browser so a
			// new user can create an account, then come back and add it here.
			open_url(kTailscaleSignupURL);
			break;
		case kMsgTailscaleAdmin:
			// Open the Tailscale web admin console.
			open_url(kTailscaleAdminURL);
			break;
		case kMsgShowPeers:
		{
			// Open (or re-use) the peers window and seed it with the latest
			// peer snapshot. fPeersWindow.IsValid() goes false once the window
			// is closed, so a new one is created on the next request.
			if (!fPeersWindow.IsValid()) {
				PeersWindow* w = new PeersWindow(this);
				fPeersWindow = BMessenger(w);
				w->Show();
			}
			fLastPeers.what = kMsgPeersData;
			fPeersWindow.SendMessage(&fLastPeers);
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
			// Which profile is actually connected (the daemon includes it while
			// a session is live). Drives the Server box + the "different
			// selection" notice via _RefreshDetails below.
			BMessage connectedArchive;
			if (message->FindMessage(kFieldConnectedProfile, &connectedArchive)
					== B_OK) {
				fConnectedProfile = VPNProfile();
				fConnectedProfile.Unarchive(connectedArchive);
				fHasConnectedProfile = true;
			} else {
				fHasConnectedProfile = false;
			}

			_UpdateForState((VPNState)state, detail);
			_ApplyStats(message);
			_UpdatePeers(message);
			_RefreshDetails();
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

	// Tailscale never uses a username/password: it authenticates through the
	// browser (SSO) or an optional pre-auth key. Skip the credentials prompt
	// entirely and connect straight away -- _SendConnectWith pulls the auth key
	// from the keystore if one was set, otherwise the daemon opens the login
	// URL.
	if (selected->fBackendType == VPN_BACKEND_TAILSCALE) {
		fLastUsedStoredCredentials = false;
		_SendConnectWith(NULL, NULL);
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
	// For a Tailscale profile, pull the optional pre-auth key from the keystore
	// and pass it transiently. Non-Tailscale profiles have no such entry, so
	// this is a no-op for them.
	BString authKey;
	if (selected->fBackendType == VPN_BACKEND_TAILSCALE
			&& load_authkey(selected->fName.String(), authKey))
		connect.AddString(kFieldAuthKey, authKey);
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

	// A Tailscale profile awaiting interactive login reports its browser
	// AuthURL in the status detail; open it once so the user can complete login.
	if (state == VPN_STATE_AUTHENTICATING)
		_MaybeOpenAuthURL(detail);

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
MainWindow::_MaybeOpenAuthURL(const char* detail)
{
	if (detail == NULL)
		return;
	// Extract the first https:// token from the status detail.
	const char* start = strstr(detail, "https://");
	if (start == NULL)
		return;
	const char* end = start;
	while (*end != '\0' && *end != ' ' && *end != '\t' && *end != '\n')
		end++;
	BString url(start, end - start);
	if (url.Length() == 0 || url == fLastAuthURL)
		return;	// already handled this login URL

	fLastAuthURL = url;
	_AppendEvent(BString("Opening login page: ").Append(url).String());
	// Open the URL in the default web browser.
	open_url(url.String());
}


void
MainWindow::_UpdatePeers(const BMessage* status)
{
	// Snapshot the peer array from the status broadcast (empty for non-
	// Tailscale sessions) and push it to the peers window if it's open.
	fLastPeers.MakeEmpty();
	fLastPeers.what = kMsgPeersData;
	BMessage peer;
	for (int32 i = 0; status->FindMessage(kFieldPeer, i, &peer) == B_OK; i++)
		fLastPeers.AddMessage(kFieldPeer, &peer);

	if (fPeersWindow.IsValid())
		fPeersWindow.SendMessage(&fLastPeers);
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

	// The Server box must describe the profile that's actually CONNECTED, not
	// whatever is highlighted in the list. When a session is live we show the
	// connected profile (broadcast by the daemon) and, if the user has selected
	// a different one, a notice so the two are never confused.
	const VPNProfile* shown = hasSelection ? selected : NULL;
	bool differs = false;
	if (fHasConnectedProfile) {
		shown = &fConnectedProfile;
		differs = hasSelection
			&& selected->fName != fConnectedProfile.fName;
	}

	if (fServerLabel != NULL) {
		if (shown != NULL) {
			char buf[128];
			snprintf(buf, sizeof(buf), "%s:%u",
				shown->fServer.String(), (unsigned)shown->fPort);
			fServerLabel->SetText(buf);
		} else {
			fServerLabel->SetText("\xe2\x80\x94");
		}
	}

	if (fProtocolLabel != NULL) {
		const char* protocol = "\xe2\x80\x94";
		if (shown != NULL) {
			if (shown->fProtocol.Length() > 0)
				protocol = shown->fProtocol.String();
			else if (shown->fBackendType == VPN_BACKEND_TAILSCALE)
				protocol = "WireGuard";	// Tailscale tunnels WireGuard
		}
		fProtocolLabel->SetText(protocol);
	}

	if (fBackendLabel != NULL) {
		const char* backend = "\xe2\x80\x94";
		if (shown != NULL) {
			switch (shown->fBackendType) {
				case VPN_BACKEND_WIREGUARD:	backend = "WireGuard";	break;
				case VPN_BACKEND_TAILSCALE:	backend = "Tailscale";	break;
				case VPN_BACKEND_IPSEC:		backend = "IPSec";		break;
				default:					backend = "OpenVPN";	break;
			}
		}
		fBackendLabel->SetText(backend);
	}

	if (fConnNotice != NULL) {
		// Fixed-length, name-free message so a long profile name can never
		// stretch the window; the connected identity is already shown above.
		fConnNotice->SetText(differs
			? "\xe2\x84\xb9 Showing the connected VPN, not the selected profile."
			: "");
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
MainWindow::_CreateTailscaleProfile(const char* name, const char* controlURL,
	const char* authKey)
{
	if (!fServer.IsValid() || name == NULL || *name == '\0')
		return;

	// Confirm before replacing an existing profile of the same name.
	for (size_t i = 0; i < fProfiles.size(); i++) {
		if (fProfiles[i].fName == name) {
			BString question;
			question << "A profile named '" << name << "' already exists.\n\n"
				   "Replace it?";
			BAlert* alert = new BAlert("overwriteProfile", question.String(),
				"Cancel", "Replace");
			alert->SetShortcut(0, B_ESCAPE);
			if (alert->Go() != 1)
				return;
			break;
		}
	}

	VPNProfile profile;
	profile.fBackendType = VPN_BACKEND_TAILSCALE;
	profile.fName = name;
	// The control server (public coordination server or a Headscale URL) rides
	// on fServer; the daemon defaults it to controlplane.tailscale.com if empty.
	profile.fServer = (controlURL != NULL && *controlURL != '\0')
		? controlURL : "controlplane.tailscale.com";
	profile.fPort = 443;
	profile.fProtocol = "";
	profile.fConfigPath = "";

	// The optional pre-auth key is a secret: keep it in the keystore, never in
	// the on-disk profile. An empty key clears any previous one (e.g. when the
	// user replaces a profile) and leaves the browser-SSO path in place.
	bool hasKey = authKey != NULL && *authKey != '\0';
	if (hasKey)
		save_authkey(name, authKey);
	else
		forget_authkey(name);

	// Optimistically select the new profile once the server echoes the list.
	fSelectedName = profile.fName;

	BMessage archive;
	profile.Archive(&archive);
	BMessage save(kMsgSaveProfile);
	save.AddMessenger(kFieldClient, BMessenger(this));
	save.AddMessage(kFieldProfile, &archive);
	fServer.SendMessage(&save);

	_AppendEvent(BString("Added Tailscale network '").Append(name).Append(
		hasKey
			? "' \xe2\x80\x94 select it and click Connect (pre-auth key set)."
			: "' \xe2\x80\x94 select it and click Connect to sign in.").String());
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
	// behind would resurface on a re-import with the same name. Same for a
	// Tailscale pre-auth key.
	forget_credentials(selected->fName.String());
	forget_authkey(selected->fName.String());

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


// The Tailscale pre-auth key gets its own keystore entry under a distinct
// identifier ("tsauth:<profile>") so it never clashes with the OpenVPN password
// stored under the bare profile name.
static BString
_authKeyId(const char* profileName)
{
	BString id("tsauth:");
	id << profileName;
	return id;
}


static bool
load_authkey(const char* profileName, BString& outKey)
{
	if (profileName == NULL || *profileName == '\0')
		return false;
	BKeyStore keystore;
	BPasswordKey key;
	if (keystore.GetKey(B_KEY_TYPE_PASSWORD, _authKeyId(profileName).String(),
			key) != B_OK)
		return false;
	outKey = key.Password();
	return outKey.Length() > 0;
}


static void
save_authkey(const char* profileName, const char* authKey)
{
	if (profileName == NULL || *profileName == '\0' || authKey == NULL
			|| *authKey == '\0')
		return;
	BKeyStore keystore;
	BString id = _authKeyId(profileName);
	// AddKey refuses to overwrite, so clear any prior key first.
	BPasswordKey existing;
	if (keystore.GetKey(B_KEY_TYPE_PASSWORD, id.String(), existing) == B_OK)
		keystore.RemoveKey(existing);
	BPasswordKey key(authKey, B_KEY_PURPOSE_NETWORK, id.String());
	keystore.AddKey(key);
}


static void
forget_authkey(const char* profileName)
{
	if (profileName == NULL || *profileName == '\0')
		return;
	BKeyStore keystore;
	BPasswordKey existing;
	if (keystore.GetKey(B_KEY_TYPE_PASSWORD, _authKeyId(profileName).String(),
			existing) == B_OK)
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
