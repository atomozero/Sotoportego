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
#include <GroupLayout.h>
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
#include "HeaderView.h"
#include "OpenVPNConfigParser.h"
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

static const char* const kBackendName	= "OpenVPN";


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
	fSinceValue(NULL),
	fDownValue(NULL),
	fUpValue(NULL),
	fProfileList(NULL),
	fEventLog(NULL),
	fAddButton(NULL),
	fRemoveButton(NULL),
	fActionButton(NULL),
	fStatusBar(NULL),
	fImportPanel(NULL),
	fProfiles(),
	fSelectedName()
{
	_BuildLayout();
	_UpdateForState(VPN_STATE_DISCONNECTED, NULL);
	_RefreshDetails();
	_EnsureSubscribed();
}


MainWindow::~MainWindow()
{
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
	menuBar->AddItem(connectionMenu);

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
		.Add(fTunnelIPValue, 1, 3);

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
			message->FindString(kFieldUsername, &user);
			message->FindString(kFieldPassword, &pass);
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
			_UpdateForState((VPNState)state, detail);
			_ApplyStats(message);
			break;
		}

		case kMsgStatsUpdate:
			_ApplyStats(message);
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

	if (!fServer.IsValid())
		return;

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

	// Always prompt for credentials -- we can't reliably know up-front
	// whether the .ovpn file requires interactive auth, and an empty
	// prompt is cheap to dismiss for cert-only configs.
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

	if (fStatusBar != NULL) {
		BString status;
		status << (int32)fProfiles.size();
		status << (fProfiles.size() == 1 ? " profile \xc2\xb7 " : " profiles \xc2\xb7 ");
		status << vpn_state_name(state);
		fStatusBar->SetText(status.String());
	}

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
			BString body("The VPN connection failed.");
			if (detail != NULL && detail[0] != '\0') {
				body << "\n\n";
				body << detail;
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

	int32 newSelection = -1;
	for (size_t i = 0; i < fProfiles.size(); i++) {
		fProfileList->AddItem(new BStringItem(fProfiles[i].fName.String()));
		if (fProfiles[i].fName == fSelectedName)
			newSelection = (int32)i;
	}

	if (newSelection < 0 && !fProfiles.empty()) {
		newSelection = 0;
		fSelectedName = fProfiles[0].fName;
	} else if (fProfiles.empty()) {
		fSelectedName = "";
	}

	if (newSelection >= 0)
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
	profile.fBackendType = VPN_BACKEND_OPENVPN;
	if (!OpenVPNConfigParser::ParseFile(path.Path(), profile)) {
		BAlert* alert = new BAlert("importFailed",
			"Could not read the selected .ovpn file.", "OK");
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

	fSelectedName = "";
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
