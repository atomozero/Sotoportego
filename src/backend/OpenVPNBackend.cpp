/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "OpenVPNBackend.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <string>

#include <Looper.h>
#include <Message.h>
#include <Messenger.h>

#include "VPNProtocol.h"


// Private 'what' codes posted from worker contexts back to the looper.
static const uint32 kMsgInternalEvent	= 'oEvt';
static const uint32 kMsgReaderExited	= 'oRDr';

// Reader buffer size; openvpn lines are short.
static const size_t kReaderBufferSize	= 2048;

// Connect attempts to the management socket before giving up. openvpn opens
// the listen socket very early but not before we return from posix_spawnp,
// so a short retry loop is enough.
static const int kMgmtConnectAttempts	= 50;	// 5s total at 100ms each
static const bigtime_t kMgmtConnectInterval	= 100000;

// Range of local TCP ports we'll try for the management interface. Picked at
// random within this range; a collision just means the retry-connect below
// fails and we surface an error.
static const int kMgmtPortBase		= 17500;
static const int kMgmtPortSpread	= 200;


extern "C" char** environ;


// --- helpers ---------------------------------------------------------------

static std::string
escape_arg(const BString& value)
{
	std::string out;
	const char* s = value.String();
	for (size_t i = 0; s[i] != '\0'; i++) {
		if (s[i] == '\\' || s[i] == '"')
			out += '\\';
		out += s[i];
	}
	return out;
}


// Synchronously run `ifconfig <args...>` (where the variadic list ends in a
// trailing NULL) and wait for it to finish. Returns true on a zero exit
// status. Errors are logged to stderr but don't otherwise propagate -- the
// caller decides whether to surface them as a connection-level error.
static bool
run_ifconfig(const char* const argv[])
{
	pid_t pid = -1;
	int rc = posix_spawnp(&pid, "ifconfig", NULL, NULL,
		(char* const*)argv, environ);
	if (rc != 0) {
		fprintf(stderr,
			"[OpenVPN] spawn(ifconfig) failed: %s\n", strerror(rc));
		return false;
	}
	int status = 0;
	if (waitpid(pid, &status, 0) != pid)
		return false;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}


// Same shape as run_ifconfig but for /bin/route. Used to install and
// uninstall the routes we need to make redirect-gateway actually work on
// Haiku.
static bool
run_route(const char* const argv[])
{
	// Build a printable command for the daemon log so the user can correlate
	// it with what they'd run by hand.
	BString line("[OpenVPN] route");
	for (int i = 1; argv[i] != NULL; i++) {
		line << " ";
		line << argv[i];
	}
	printf("%s\n", line.String());

	pid_t pid = -1;
	int rc = posix_spawnp(&pid, "route", NULL, NULL,
		(char* const*)argv, environ);
	if (rc != 0) {
		fprintf(stderr,
			"[OpenVPN] spawn(route) failed: %s\n", strerror(rc));
		return false;
	}
	int status = 0;
	if (waitpid(pid, &status, 0) != pid)
		return false;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}


// --- OpenVPNBackend --------------------------------------------------------

OpenVPNBackend::OpenVPNBackend()
	:
	VPNBackend("OpenVPNBackend"),
	fState(VPN_STATE_DISCONNECTED),
	fStats(),
	fProfile(),
	fLocalIP(),
	fRemoteIP(),
	fAuthUsername(),
	fAuthPassword(),
	fOrigGateway(),
	fOrigGatewayIface(),
	fTunPeer(),
	fInstalledServerIP(),
	fRoutesInstalled(false),
	fManagement(),
	fPid(-1),
	fSocket(-1),
	fMgmtPort(0),
	fReader(-1),
	fStopRequested(false)
{
	srand((unsigned)time(NULL) ^ (unsigned)find_thread(NULL));
}


OpenVPNBackend::~OpenVPNBackend()
{
	_Cleanup(true);
}


status_t
OpenVPNBackend::Connect(const VPNProfile& profile)
{
	if (fState != VPN_STATE_DISCONNECTED && fState != VPN_STATE_ERROR)
		return B_NOT_ALLOWED;

	if (Looper() == NULL) {
		// The backend must be attached to the daemon's looper before use, so
		// that BMessenger(this) is addressable from the reader thread.
		return B_NO_INIT;
	}

	if (profile.fConfigPath.Length() == 0) {
		_SetState(VPN_STATE_ERROR, "profile has no .ovpn config path");
		return B_BAD_VALUE;
	}

	fProfile = profile;
	fStats.Reset();
	fLocalIP = "";
	fRemoteIP = profile.fServer;
	fStopRequested = false;

	printf("[OpenVPN] connect requested: profile='%s' config='%s'\n",
		fProfile.fName.String(), fProfile.fConfigPath.String());

	// Haiku cannot allocate TUN/TAP devices dynamically; openvpn's open_tun
	// just iterates /dev/tun/0 .. /dev/tun/255 and uses the first one that
	// exists. `ifconfig tun/0 up` publishes that device through the kernel
	// add-on. Safe to run if the interface already exists.
	const char* const ifconfigUp[] = { "ifconfig", "tun/0", "up", NULL };
	if (!run_ifconfig(ifconfigUp)) {
		_SetState(VPN_STATE_ERROR,
			"could not create tun/0 (is the tunnel kernel add-on present?)");
		return B_ERROR;
	}

	if (!_SpawnOpenVPN(fProfile)) {
		_SetState(VPN_STATE_ERROR,
			"could not start openvpn (is it installed?)");
		return B_ERROR;
	}

	_SetState(VPN_STATE_CONNECTING);

	if (!_ConnectManagementSocket()) {
		_Cleanup(true);
		_SetState(VPN_STATE_ERROR, "could not reach openvpn management port");
		return B_ERROR;
	}

	// Subscribe to the events we care about, then let openvpn proceed past
	// the management-hold. `log on` is what makes openvpn echo its stderr
	// lines through management, which is how _ScanLogLine() picks up the
	// values used by the route fix-up.
	_SendCommand("state on");
	_SendCommand("bytecount 1");
	_SendCommand("log on all");
	_SendCommand("hold release");

	_StartReader();
	return B_OK;
}


status_t
OpenVPNBackend::Disconnect()
{
	if (fState == VPN_STATE_DISCONNECTED)
		return B_OK;

	printf("[OpenVPN] disconnect requested\n");
	fStopRequested = true;

	if (fSocket >= 0)
		_SendCommand("signal SIGTERM");
	else if (fPid > 0)
		kill(fPid, SIGTERM);

	return B_OK;
}


VPNState
OpenVPNBackend::State() const
{
	return fState;
}


VPNStats
OpenVPNBackend::Stats() const
{
	return fStats;
}


const char*
OpenVPNBackend::BackendName() const
{
	return "OpenVPN";
}


BString
OpenVPNBackend::LocalIP() const
{
	return fLocalIP;
}


BString
OpenVPNBackend::RemoteIP() const
{
	return fRemoteIP;
}


void
OpenVPNBackend::SetCredentials(const BString& user, const BString& pass)
{
	fAuthUsername = user;
	fAuthPassword = pass;
}


void
OpenVPNBackend::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgInternalEvent:
		{
			OpenVPNEvent event;
			int32 type = OPENVPN_EVENT_UNKNOWN;
			int32 mapped = (int32)VPN_STATE_ERROR;
			int64 bytesIn = 0, bytesOut = 0;
			const char* raw = "";
			const char* stateName = "";
			const char* stateDetail = "";
			const char* localIP = "";
			const char* remoteIP = "";
			const char* realm = "";
			const char* msg = "";

			message->FindInt32("type", &type);
			message->FindInt32("mapped", &mapped);
			message->FindInt64("bytesIn", &bytesIn);
			message->FindInt64("bytesOut", &bytesOut);
			message->FindString("raw", &raw);
			message->FindString("stateName", &stateName);
			message->FindString("stateDetail", &stateDetail);
			message->FindString("localIP", &localIP);
			message->FindString("remoteIP", &remoteIP);
			message->FindString("realm", &realm);
			message->FindString("message", &msg);

			event.type = (OpenVPNEventType)type;
			event.mappedState = (VPNState)mapped;
			event.bytesIn = (uint64_t)bytesIn;
			event.bytesOut = (uint64_t)bytesOut;
			event.raw = raw;
			event.stateName = stateName;
			event.stateDetail = stateDetail;
			event.localIP = localIP;
			event.remoteIP = remoteIP;
			event.realm = realm;
			event.message = msg;

			_HandleManagementEvent(event);
			break;
		}

		case kMsgReaderExited:
			// The reader is gone; tear the rest down and report Disconnected
			// (unless we already landed on ERROR from a FATAL/AUTH_FAILED).
			_Cleanup(true);
			if (fState != VPN_STATE_ERROR)
				_SetState(VPN_STATE_DISCONNECTED);
			break;

		default:
			VPNBackend::MessageReceived(message);
			break;
	}
}


// --- lifecycle -------------------------------------------------------------

bool
OpenVPNBackend::_SpawnOpenVPN(const VPNProfile& profile)
{
	// Pick a port now so the same string can go into the argv. A real
	// collision is rare and surfaces as a connect failure below.
	fMgmtPort = kMgmtPortBase + (rand() % kMgmtPortSpread);
	char portStr[16];
	snprintf(portStr, sizeof(portStr), "%d", fMgmtPort);

	// Build argv. posix_spawnp wants char*; the strings live for the
	// duration of the call only, so casting away const here is fine.
	// --route-noexec stops openvpn from installing routes itself. The Haiku
	// port hardcodes the physical interface for every route it adds, so
	// the redirect-gateway routes end up on wifi instead of tun/0 and
	// traffic disappears. We re-install them ourselves in _InstallRoutes()
	// once we have CONNECTED and have parsed the values we need out of
	// openvpn's log stream.
	char* argv[] = {
		(char*)"openvpn",
		(char*)"--config", (char*)profile.fConfigPath.String(),
		(char*)"--management", (char*)"127.0.0.1", portStr,
		(char*)"--management-hold",
		(char*)"--management-query-passwords",
		(char*)"--route-noexec",
		(char*)"--verb", (char*)"3",
		NULL
	};

	pid_t pid = -1;
	int rc = posix_spawnp(&pid, "openvpn", NULL, NULL, argv, environ);
	if (rc != 0) {
		fprintf(stderr, "[OpenVPN] posix_spawnp failed: %s\n", strerror(rc));
		return false;
	}

	fPid = pid;
	printf("[OpenVPN] spawned openvpn pid=%d mgmt=127.0.0.1:%d\n",
		(int)fPid, fMgmtPort);
	return true;
}


bool
OpenVPNBackend::_ConnectManagementSocket()
{
	for (int attempt = 0; attempt < kMgmtConnectAttempts; attempt++) {
		// If the child died while we were waiting, abort early.
		int status = 0;
		pid_t reaped = waitpid(fPid, &status, WNOHANG);
		if (reaped == fPid) {
			fprintf(stderr,
				"[OpenVPN] child exited before management was ready\n");
			fPid = -1;
			return false;
		}

		int fd = socket(AF_INET, SOCK_STREAM, 0);
		if (fd < 0) {
			snooze(kMgmtConnectInterval);
			continue;
		}
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(fMgmtPort);
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
			fSocket = fd;
			return true;
		}
		close(fd);
		snooze(kMgmtConnectInterval);
	}
	return false;
}


void
OpenVPNBackend::_StartReader()
{
	fReader = spawn_thread(_ReaderEntry, "openvpn-reader",
		B_NORMAL_PRIORITY, this);
	if (fReader < B_OK) {
		fReader = -1;
		fprintf(stderr, "[OpenVPN] spawn_thread failed\n");
		_Cleanup(true);
		_SetState(VPN_STATE_ERROR, "could not start reader thread");
		return;
	}
	resume_thread(fReader);
}


int32
OpenVPNBackend::_ReaderEntry(void* self)
{
	return ((OpenVPNBackend*)self)->_RunReaderLoop();
}


int32
OpenVPNBackend::_RunReaderLoop()
{
	char buffer[kReaderBufferSize];
	while (true) {
		ssize_t got = recv(fSocket, buffer, sizeof(buffer), 0);
		if (got <= 0)
			break;

		std::string chunk(buffer, (size_t)got);
		std::vector<OpenVPNEvent> events = fManagement.Feed(chunk);
		for (size_t i = 0; i < events.size(); i++) {
			// Credentials are answered right here on the I/O thread so we
			// stay responsive to openvpn's prompt; everything else gets
			// dispatched to the looper.
			const OpenVPNEvent& event = events[i];
			if (event.type == OPENVPN_EVENT_PASSWORD_REQUEST
					&& fAuthUsername.Length() > 0) {
				char line[1024];
				snprintf(line, sizeof(line), "username \"%s\" \"%s\"",
					event.realm.c_str(),
					escape_arg(fAuthUsername).c_str());
				_SendCommand(line);
				snprintf(line, sizeof(line), "password \"%s\" \"%s\"",
					event.realm.c_str(),
					escape_arg(fAuthPassword).c_str());
				_SendCommand(line);
			}
			_PostEvent(event);
		}
	}

	BMessenger(this).SendMessage(kMsgReaderExited);
	return B_OK;
}


void
OpenVPNBackend::_Cleanup(bool wait)
{
	if (fSocket >= 0) {
		// Closing kicks any blocked recv() in the reader thread, if it is
		// still alive.
		shutdown(fSocket, SHUT_RDWR);
		close(fSocket);
		fSocket = -1;
	}

	if (fReader > 0 && wait) {
		status_t exitCode = 0;
		wait_for_thread(fReader, &exitCode);
		fReader = -1;
	}

	if (fPid > 0) {
		// Give openvpn a moment to wind down on its own; if it doesn't,
		// escalate to SIGTERM and then SIGKILL.
		int status = 0;
		pid_t reaped = -1;
		for (int i = 0; i < 20; i++) {
			reaped = waitpid(fPid, &status, WNOHANG);
			if (reaped == fPid)
				break;
			snooze(100000);
		}
		if (reaped != fPid) {
			kill(fPid, SIGTERM);
			for (int i = 0; i < 10; i++) {
				reaped = waitpid(fPid, &status, WNOHANG);
				if (reaped == fPid)
					break;
				snooze(100000);
			}
		}
		if (reaped != fPid) {
			kill(fPid, SIGKILL);
			waitpid(fPid, &status, 0);
		}
		printf("[OpenVPN] reaped openvpn pid=%d\n", (int)fPid);
		fPid = -1;
	}

	// Drop the routes we installed in _InstallRoutes BEFORE tearing the tun
	// device down, otherwise the route command can fail when the interface
	// is already gone.
	_RemoveRoutes();

	// Tear tun/0 out of the interface list entirely. `ifconfig tun/0 down`
	// only deactivates it -- the interface stays around with whatever IP
	// openvpn pushed onto it, and the next Connect would inherit a stale
	// address. `--delete` removes the interface; the kernel tunnel add-on
	// republishes it next time we ifconfig it up.
	const char* const ifconfigDelete[] = {
		"ifconfig", "--delete", "tun/0", NULL
	};
	run_ifconfig(ifconfigDelete);

	fLocalIP = "";
	fAuthUsername = "";
	fAuthPassword = "";
	fOrigGateway = "";
	fOrigGatewayIface = "";
	fTunPeer = "";
}


// --- protocol --------------------------------------------------------------

void
OpenVPNBackend::_SendCommand(const char* line)
{
	if (fSocket < 0 || line == NULL)
		return;
	size_t length = strlen(line);
	send(fSocket, line, length, 0);
	send(fSocket, "\n", 1, 0);
}


void
OpenVPNBackend::_PostEvent(const OpenVPNEvent& event)
{
	BMessage message(kMsgInternalEvent);
	message.AddInt32("type", (int32)event.type);
	message.AddInt32("mapped", (int32)event.mappedState);
	message.AddInt64("bytesIn", (int64)event.bytesIn);
	message.AddInt64("bytesOut", (int64)event.bytesOut);
	message.AddString("raw", event.raw.c_str());
	message.AddString("stateName", event.stateName.c_str());
	message.AddString("stateDetail", event.stateDetail.c_str());
	message.AddString("localIP", event.localIP.c_str());
	message.AddString("remoteIP", event.remoteIP.c_str());
	message.AddString("realm", event.realm.c_str());
	message.AddString("message", event.message.c_str());
	BMessenger(this).SendMessage(&message);
}


void
OpenVPNBackend::_HandleManagementEvent(const OpenVPNEvent& event)
{
	switch (event.type) {
		case OPENVPN_EVENT_STATE:
			// openvpn sends >STATE:EXITING just before it dies; if we have
			// already recorded a more specific error (auth-failed, fatal),
			// keep that as the visible state instead of overwriting it with
			// a generic Disconnected.
			if (event.mappedState == VPN_STATE_DISCONNECTED
					&& fState == VPN_STATE_ERROR) {
				break;
			}
			if (event.mappedState == VPN_STATE_CONNECTED) {
				fStats.fConnectedSince = time(NULL);
				if (!event.localIP.empty())
					fLocalIP = event.localIP.c_str();
				if (!event.remoteIP.empty())
					fRemoteIP = event.remoteIP.c_str();
				// All the values needed for the route fix-up have been
				// scanned out of the preceding log lines (ROUTE_GATEWAY
				// and PUSH_REPLY). event.remoteIP is the VPN server's
				// public IP, the third piece we need.
				_InstallRoutes(BString(event.remoteIP.c_str()));
			}
			_SetState(event.mappedState,
				event.stateDetail.empty() ? NULL : event.stateDetail.c_str());
			break;

		case OPENVPN_EVENT_BYTECOUNT:
			fStats.fBytesIn = event.bytesIn;
			fStats.fBytesOut = event.bytesOut;
			NotifyStats(fStats);
			break;

		case OPENVPN_EVENT_PASSWORD_REQUEST:
			printf("[OpenVPN] credentials requested for realm '%s'\n",
				event.realm.c_str());
			if (fAuthUsername.Length() == 0) {
				// No credentials in hand and the daemon has no UI of its
				// own; openvpn will time out and exit, which we'll surface
				// via the FATAL / process-exit path.
				_SetState(VPN_STATE_AUTHENTICATING,
					"credentials required but none provided");
			}
			break;

		case OPENVPN_EVENT_AUTH_FAILED:
			_SetState(VPN_STATE_ERROR, "authentication failed");
			break;

		case OPENVPN_EVENT_FATAL:
			_SetState(VPN_STATE_ERROR,
				event.message.empty() ? "fatal error" : event.message.c_str());
			break;

		case OPENVPN_EVENT_LOG:
		case OPENVPN_EVENT_INFO:
			if (!event.message.empty()) {
				printf("[OpenVPN] %s\n", event.message.c_str());
				_ScanLogLine(event.message);
			}
			break;

		default:
			break;
	}
}


void
OpenVPNBackend::_SetState(VPNState state, const char* detail)
{
	fState = state;
	printf("[OpenVPN] state -> %s%s%s\n", vpn_state_name(state),
		detail != NULL ? ": " : "", detail != NULL ? detail : "");
	NotifyStateChanged(state, detail);
}


// --- log scanning and route fix-up ----------------------------------------

// Lift the first whitespace-delimited token starting at `pos` out of `s`.
// Stops at any of " \t,'\"". Returns the token (possibly empty).
static std::string
take_token(const std::string& s, size_t pos)
{
	while (pos < s.length() && (s[pos] == ' ' || s[pos] == '\t'))
		pos++;
	size_t end = pos;
	while (end < s.length()) {
		char c = s[end];
		if (c == ' ' || c == '\t' || c == ',' || c == '\'' || c == '"'
				|| c == '\n' || c == '\r') {
			break;
		}
		end++;
	}
	return s.substr(pos, end - pos);
}


void
OpenVPNBackend::_ScanLogLine(const std::string& line)
{
	// openvpn prints the underlying default route once it has worked out
	// where to send tunnel packets:
	//   ROUTE_GATEWAY 192.168.188.1 IFACE=/dev/net/iprowifi4965/0
	if (fOrigGateway.Length() == 0) {
		size_t pos = line.find("ROUTE_GATEWAY ");
		if (pos != std::string::npos) {
			std::string gw = take_token(line, pos + 14);
			size_t ifacePos = line.find("IFACE=", pos);
			std::string iface;
			if (ifacePos != std::string::npos)
				iface = take_token(line, ifacePos + 6);
			if (!gw.empty() && !iface.empty()) {
				fOrigGateway = gw.c_str();
				fOrigGatewayIface = iface.c_str();
				printf("[OpenVPN] captured default route: %s via %s\n",
					fOrigGateway.String(), fOrigGatewayIface.String());
			}
		}
	}

	// The PUSH_REPLY carries the in-tunnel peer/gateway under a comma-
	// separated key/value pair like "route-gateway 10.245.243.246". The
	// PUSH_REPLY message also contains commas, which is why we needed the
	// LOG-parser fix in OpenVPNManagement; the substring search here is
	// agnostic to surrounding noise.
	if (fTunPeer.Length() == 0) {
		size_t pos = line.find("route-gateway ");
		if (pos != std::string::npos) {
			std::string peer = take_token(line, pos + 14);
			if (!peer.empty()) {
				fTunPeer = peer.c_str();
				printf("[OpenVPN] captured tunnel peer: %s\n",
					fTunPeer.String());
			}
		}
	}
}


void
OpenVPNBackend::_InstallRoutes(const BString& vpnServerIP)
{
	if (fRoutesInstalled)
		return;

	// All three values are needed -- without them we can't even guess at the
	// right route commands, so refuse rather than do something destructive.
	if (fOrigGateway.Length() == 0 || fOrigGatewayIface.Length() == 0
			|| fTunPeer.Length() == 0 || vpnServerIP.Length() == 0) {
		fprintf(stderr,
			"[OpenVPN] missing routing info, skipping route fix-up "
			"(server=%s gw=%s iface=%s peer=%s)\n",
			vpnServerIP.String(),
			fOrigGateway.String(),
			fOrigGatewayIface.String(),
			fTunPeer.String());
		return;
	}

	// 1) Pin the VPN server to the underlying default route so openvpn's
	// UDP/TCP packets don't try to flow back through the tunnel they're
	// carrying.
	const char* const serverPin[] = {
		"route", "add", fOrigGatewayIface.String(), "inet",
		vpnServerIP.String(), "gw", fOrigGateway.String(),
		"netmask", "255.255.255.255", NULL
	};
	run_route(serverPin);

	// 2,3) Replace the system default route with two /1 routes pointing at
	// the tunnel peer over tun/0. Two halves win over the existing 0.0.0.0/0
	// by longest-prefix match, so we don't have to touch the original
	// default.
	const char* const lower[] = {
		"route", "add", "tun/0", "inet", "0.0.0.0",
		"gw", fTunPeer.String(), "netmask", "128.0.0.0", NULL
	};
	const char* const upper[] = {
		"route", "add", "tun/0", "inet", "128.0.0.0",
		"gw", fTunPeer.String(), "netmask", "128.0.0.0", NULL
	};
	run_route(lower);
	run_route(upper);

	fInstalledServerIP = vpnServerIP;
	fRoutesInstalled = true;
}


void
OpenVPNBackend::_RemoveRoutes()
{
	if (!fRoutesInstalled)
		return;

	const char* const upper[] = {
		"route", "delete", "tun/0", "inet", "128.0.0.0",
		"gw", fTunPeer.String(), "netmask", "128.0.0.0", NULL
	};
	const char* const lower[] = {
		"route", "delete", "tun/0", "inet", "0.0.0.0",
		"gw", fTunPeer.String(), "netmask", "128.0.0.0", NULL
	};
	const char* const serverPin[] = {
		"route", "delete", fOrigGatewayIface.String(), "inet",
		fInstalledServerIP.String(), "gw", fOrigGateway.String(),
		"netmask", "255.255.255.255", NULL
	};
	run_route(upper);
	run_route(lower);
	run_route(serverPin);

	fRoutesInstalled = false;
	fInstalledServerIP = "";
}
