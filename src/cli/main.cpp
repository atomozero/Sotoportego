/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 *
 * sotoportego_cli -- a headless client for the Sotoportego daemon. It drives the
 * same IPC the GUI uses, so a connection can be scripted or tested without the
 * desktop. Crucially it connects a profile BY NAME, so automation targets an
 * exact profile instead of "whatever is selected".
 *
 *   sotoportego_cli list                     list saved profiles
 *   sotoportego_cli status                   print the current session status
 *   sotoportego_cli peers                    list tailnet peers (Tailscale)
 *   sotoportego_cli connect <profile-name>   connect a saved profile
 *   sotoportego_cli disconnect               tear down the current session
 *   sotoportego_cli watch [seconds]          print status changes for a while
 *   sotoportego_cli exit-node <peer|off>     route via a Tailscale exit node
 *                                            (peer name / tailnet IP / node key)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Application.h>
#include <Message.h>
#include <MessageRunner.h>
#include <Messenger.h>
#include <Roster.h>
#include <OS.h>
#include <String.h>

#include "VPNProfile.h"
#include "VPNProtocol.h"
#include "VPNState.h"
#include "VPNStats.h"


enum Command {
	CMD_HELP,
	CMD_LIST,
	CMD_STATUS,
	CMD_PEERS,
	CMD_CONNECT,
	CMD_DISCONNECT,
	CMD_WATCH,
	CMD_EXITNODE
};

// CLI-private timer messages.
static const uint32 kMsgDeadline	= 'cDl';	// hard overall timeout
static const uint32 kMsgWatchDone	= 'cWd';	// watch window elapsed


class SotoportegoCLI : public BApplication {
public:
								SotoportegoCLI(Command cmd, const BString& arg,
									bigtime_t watchSecs);
	virtual						~SotoportegoCLI();

	virtual	void				ReadyToRun();
	virtual	void				MessageReceived(BMessage* message);

			int					ExitCode() const { return fExitCode; }

private:
			status_t			_EnsureServer();
			void				_Subscribe();
			void				_RequestStatus();
			void				_ConnectByName(const BMessage* profileList);
			void				_ResolveAndSetExitNode(const BMessage* status);
			void				_PrintStatus(const BMessage* status);
			void				_PrintPeers(const BMessage* status);
			void				_Finish(int code);

			Command				fCmd;
			BString				fArg;
			bigtime_t			fWatchSecs;
			BMessenger			fServer;
			BMessageRunner*		fDeadline;
			BMessageRunner*		fWatchTimer;
			bool				fConnectedSeen;
			int					fExitCode;
};


SotoportegoCLI::SotoportegoCLI(Command cmd, const BString& arg,
	bigtime_t watchSecs)
	:
	BApplication(kCLISignature),
	fCmd(cmd),
	fArg(arg),
	fWatchSecs(watchSecs),
	fDeadline(NULL),
	fWatchTimer(NULL),
	fConnectedSeen(false),
	fExitCode(0)
{
}


SotoportegoCLI::~SotoportegoCLI()
{
	delete fDeadline;
	delete fWatchTimer;
}


void
SotoportegoCLI::ReadyToRun()
{
	if (_EnsureServer() != B_OK) {
		fprintf(stderr, "[cli] could not reach the Sotoportego daemon\n");
		_Finish(1);
		return;
	}

	// A hard deadline so the tool can never hang. connect/watch need longer.
	bigtime_t deadline = 20000000;	// 20s default
	if (fCmd == CMD_CONNECT)
		deadline = 120000000;		// 2 min (SSO / handshake can be slow)
	else if (fCmd == CMD_WATCH)
		deadline = fWatchSecs * 1000000 + 5000000;
	BMessage tmo(kMsgDeadline);
	fDeadline = new BMessageRunner(BMessenger(this), &tmo, deadline, 1);

	switch (fCmd) {
		case CMD_LIST:
			// The daemon hands the profile-list snapshot to new subscribers.
			_Subscribe();
			break;
		case CMD_STATUS:
		case CMD_PEERS:
		case CMD_EXITNODE:
			_RequestStatus();
			break;
		case CMD_CONNECT:
			// Subscribing yields the profile-list snapshot; we match + connect.
			_Subscribe();
			break;
		case CMD_DISCONNECT:
		{
			_Subscribe();
			BMessage req(kMsgDisconnect);
			req.AddMessenger(kFieldClient, BMessenger(this));
			fServer.SendMessage(&req);
			printf("[cli] disconnect requested\n");
			break;
		}
		case CMD_WATCH:
		{
			_Subscribe();
			_RequestStatus();
			printf("[cli] watching for %llds...\n", (long long)fWatchSecs);
			BMessage done(kMsgWatchDone);
			fWatchTimer = new BMessageRunner(BMessenger(this), &done,
				fWatchSecs * 1000000, 1);
			break;
		}
		default:
			_Finish(2);
			break;
	}
}


status_t
SotoportegoCLI::_EnsureServer()
{
	status_t launch = be_roster->Launch(kServerSignature);
	if (launch != B_OK && launch != B_ALREADY_RUNNING) {
		fprintf(stderr, "[cli] launch(%s) failed: %s\n", kServerSignature,
			strerror(launch));
		return launch;
	}
	for (int attempt = 0; attempt < 30; attempt++) {
		fServer = BMessenger(kServerSignature);
		if (fServer.IsValid())
			return B_OK;
		snooze(100000);
	}
	return B_ERROR;
}


void
SotoportegoCLI::_Subscribe()
{
	BMessage sub(kMsgSubscribe);
	sub.AddMessenger(kFieldClient, BMessenger(this));
	fServer.SendMessage(&sub);
}


void
SotoportegoCLI::_RequestStatus()
{
	BMessage req(kMsgGetStatus);
	req.AddMessenger(kFieldClient, BMessenger(this));
	fServer.SendMessage(&req);
}


void
SotoportegoCLI::_ConnectByName(const BMessage* profileList)
{
	VPNProfile match;
	bool found = false;
	BMessage archived;
	for (int32 i = 0;
			profileList->FindMessage(kFieldProfile, i, &archived) == B_OK; i++) {
		VPNProfile p;
		if (p.Unarchive(archived) == B_OK && p.fName == fArg) {
			match = p;
			found = true;
			break;
		}
	}
	if (!found) {
		fprintf(stderr, "[cli] no profile named '%s' (try: sotoportego_cli "
			"list)\n", fArg.String());
		_Finish(1);
		return;
	}

	_Subscribe();
	BMessage archive;
	match.Archive(&archive);
	BMessage connect(kMsgConnect);
	connect.AddMessenger(kFieldClient, BMessenger(this));
	connect.AddMessage(kFieldProfile, &archive);
	printf("[cli] connecting '%s' (%s)...\n", match.fName.String(),
		match.fBackendType == VPN_BACKEND_TAILSCALE ? "Tailscale"
			: match.fBackendType == VPN_BACKEND_WIREGUARD ? "WireGuard"
			: match.fBackendType == VPN_BACKEND_OPENVPN ? "OpenVPN" : "?");
	fServer.SendMessage(&connect);
}


void
SotoportegoCLI::_ResolveAndSetExitNode(const BMessage* status)
{
	BString key;
	if (fArg == "off" || fArg == "none" || fArg.Length() == 0) {
		// Clear the exit node.
	} else {
		// Match the argument against each peer's name, tailnet IP or node key.
		BMessage peer;
		bool matched = false;
		for (int32 i = 0;
				status->FindMessage(kFieldPeer, i, &peer) == B_OK; i++) {
			const char* name = NULL;
			const char* ip = NULL;
			const char* nodeKey = NULL;
			bool exitCap = false;
			peer.FindString(kFieldPeerName, &name);
			peer.FindString(kFieldPeerIP, &ip);
			peer.FindString(kFieldPeerNodeKey, &nodeKey);
			peer.FindBool(kFieldPeerExitCap, &exitCap);
			if ((name != NULL && fArg == name) || (ip != NULL && fArg == ip)
					|| (nodeKey != NULL && fArg == nodeKey)) {
				if (!exitCap) {
					fprintf(stderr, "[cli] peer '%s' is not an exit node "
						"(doesn't advertise 0.0.0.0/0)\n", fArg.String());
					_Finish(1);
					return;
				}
				if (nodeKey != NULL)
					key = nodeKey;
				matched = true;
				break;
			}
		}
		if (!matched) {
			fprintf(stderr, "[cli] no peer matching '%s' (try: sotoportego_cli "
				"peers)\n", fArg.String());
			_Finish(1);
			return;
		}
	}

	BMessage set(kMsgSetExitNode);
	set.AddString(kFieldExitNodeKey, key);
	set.AddMessenger(kFieldClient, BMessenger(this));
	fServer.SendMessage(&set);
	printf("[cli] exit node %s\n",
		key.Length() > 0 ? "set" : "cleared (direct routing)");
	_Finish(0);
}


void
SotoportegoCLI::_PrintStatus(const BMessage* status)
{
	int32 state = VPN_STATE_DISCONNECTED;
	status->FindInt32(kFieldState, &state);
	const char* backend = NULL;
	status->FindString(kFieldBackend, &backend);
	const char* localIP = NULL;
	const char* remoteIP = NULL;
	status->FindString(kFieldLocalIP, &localIP);
	status->FindString(kFieldRemoteIP, &remoteIP);

	printf("state:   %s\n", vpn_state_name((VPNState)state));
	if (backend != NULL && *backend != '\0')
		printf("backend: %s\n", backend);
	if (localIP != NULL && *localIP != '\0')
		printf("local:   %s\n", localIP);
	if (remoteIP != NULL && *remoteIP != '\0')
		printf("remote:  %s\n", remoteIP);
}


void
SotoportegoCLI::_PrintPeers(const BMessage* status)
{
	BMessage peer;
	int count = 0;
	for (int32 i = 0; status->FindMessage(kFieldPeer, i, &peer) == B_OK; i++) {
		const char* name = NULL;
		const char* ip = NULL;
		const char* path = NULL;
		bool online = false;
		bool exitCap = false;
		bool exitOn = false;
		peer.FindString(kFieldPeerName, &name);
		peer.FindString(kFieldPeerIP, &ip);
		peer.FindString(kFieldPeerPath, &path);
		int64 tx = 0, rx = 0;
		peer.FindBool(kFieldPeerOnline, &online);
		peer.FindBool(kFieldPeerExitCap, &exitCap);
		peer.FindBool(kFieldPeerExitOn, &exitOn);
		peer.FindInt64(kFieldPeerTx, &tx);
		peer.FindInt64(kFieldPeerRx, &rx);

		printf("  %-20s %-16s %-6s %-8s  \xe2\x86\x91%-8lld \xe2\x86\x93%-8lld %s\n",
			name != NULL ? name : "(unknown)",
			ip != NULL && *ip != '\0' ? ip : "-",
			path != NULL ? path : "-",
			online ? "online" : "offline",
			(long long)tx, (long long)rx,
			exitOn ? "exit:ACTIVE" : (exitCap ? "exit:available" : ""));
		count++;
	}
	if (count == 0)
		printf("  (no peers)\n");
}


void
SotoportegoCLI::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgListProfiles:
			if (fCmd == CMD_CONNECT) {
				_ConnectByName(message);
			} else {	// CMD_LIST
				VPNProfile p;
				BMessage archived;
				int n = 0;
				for (int32 i = 0; message->FindMessage(kFieldProfile, i,
						&archived) == B_OK; i++) {
					if (p.Unarchive(archived) != B_OK)
						continue;
					const char* b = p.fBackendType == VPN_BACKEND_TAILSCALE
						? "Tailscale" : p.fBackendType == VPN_BACKEND_WIREGUARD
						? "WireGuard" : p.fBackendType == VPN_BACKEND_OPENVPN
						? "OpenVPN" : "?";
					printf("  %-28s [%s]\n", p.fName.String(), b);
					n++;
				}
				if (n == 0)
					printf("  (no saved profiles)\n");
				_Finish(0);
			}
			break;

		case kMsgStatusUpdate:
		{
			if (fCmd == CMD_STATUS) {
				_PrintStatus(message);
				_Finish(0);
			} else if (fCmd == CMD_PEERS) {
				_PrintPeers(message);
				_Finish(0);
			} else if (fCmd == CMD_EXITNODE) {
				_ResolveAndSetExitNode(message);
			} else if (fCmd == CMD_CONNECT) {
				int32 state = VPN_STATE_DISCONNECTED;
				message->FindInt32(kFieldState, &state);
				const char* detail = NULL;
				message->FindString(kFieldDetail, &detail);
				printf("[cli] %s%s%s\n", vpn_state_name((VPNState)state),
					detail != NULL ? " - " : "", detail != NULL ? detail : "");
				if (state == VPN_STATE_CONNECTED) {
					printf("[cli] connected; leaving the session up\n");
					_Finish(0);
				} else if (state == VPN_STATE_ERROR) {
					_Finish(1);
				}
			} else if (fCmd == CMD_DISCONNECT) {
				int32 state = VPN_STATE_DISCONNECTED;
				message->FindInt32(kFieldState, &state);
				if (state == VPN_STATE_DISCONNECTED) {
					printf("[cli] disconnected\n");
					_Finish(0);
				}
			} else if (fCmd == CMD_WATCH) {
				int32 state = VPN_STATE_DISCONNECTED;
				message->FindInt32(kFieldState, &state);
				const char* detail = NULL;
				message->FindString(kFieldDetail, &detail);
				printf("[watch] %s%s%s\n", vpn_state_name((VPNState)state),
					detail != NULL ? " - " : "", detail != NULL ? detail : "");
			}
			break;
		}

		case kMsgWatchDone:
			printf("[cli] watch window elapsed\n");
			_Finish(0);
			break;

		case kMsgDeadline:
			fprintf(stderr, "[cli] timed out\n");
			_Finish(fConnectedSeen ? 0 : 1);
			break;

		default:
			BApplication::MessageReceived(message);
			break;
	}
}


void
SotoportegoCLI::_Finish(int code)
{
	fExitCode = code;
	PostMessage(B_QUIT_REQUESTED);
}


static Command
parse_command(const char* verb)
{
	if (strcmp(verb, "list") == 0)			return CMD_LIST;
	if (strcmp(verb, "status") == 0)		return CMD_STATUS;
	if (strcmp(verb, "peers") == 0)			return CMD_PEERS;
	if (strcmp(verb, "connect") == 0)		return CMD_CONNECT;
	if (strcmp(verb, "disconnect") == 0)	return CMD_DISCONNECT;
	if (strcmp(verb, "watch") == 0)			return CMD_WATCH;
	if (strcmp(verb, "exit-node") == 0)		return CMD_EXITNODE;
	return CMD_HELP;
}


static void
usage()
{
	printf(
		"Usage: sotoportego_cli <command> [args]\n"
		"  list                     list saved profiles\n"
		"  status                   print the current session status\n"
		"  peers                    list tailnet peers (Tailscale)\n"
		"  connect <profile-name>   connect a saved profile by name\n"
		"  disconnect               tear down the current session\n"
		"  watch [seconds]          print status changes (default 60s)\n"
		"  exit-node <peer|off>     route via a Tailscale exit node\n"
		"                           (peer name / tailnet IP / node key; "
		"'off' clears)\n");
}


int
main(int argc, char** argv)
{
	if (argc < 2) {
		usage();
		return 2;
	}
	Command cmd = parse_command(argv[1]);
	if (cmd == CMD_HELP) {
		usage();
		return 2;
	}

	BString arg;
	bigtime_t watchSecs = 60;
	if (cmd == CMD_CONNECT || cmd == CMD_EXITNODE) {
		if (argc < 3) {
			fprintf(stderr, "[cli] '%s' needs an argument\n", argv[1]);
			usage();
			return 2;
		}
		arg = argv[2];
	} else if (cmd == CMD_WATCH && argc >= 3) {
		watchSecs = atoi(argv[2]);
		if (watchSecs <= 0)
			watchSecs = 60;
	}

	SotoportegoCLI app(cmd, arg, watchSecs);
	app.Run();
	return app.ExitCode();
}
