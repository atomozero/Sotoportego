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

#include <Autolock.h>
#include <Directory.h>
#include <File.h>
#include <FindDirectory.h>
#include <Looper.h>
#include <Message.h>
#include <MessageRunner.h>
#include <Messenger.h>
#include <Path.h>

#include "VPNProtocol.h"


// Private 'what' codes posted from worker contexts back to the looper.
static const uint32 kMsgInternalEvent	= 'oEvt';
static const uint32 kMsgReaderExited	= 'oRDr';
// Posted to the looper (by BMessageRunner fMgmtPoll, and once immediately from
// Connect) to drive one management-socket connect attempt.
static const uint32 kMsgTryMgmtConnect	= 'oTMC';

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
	// The management protocol is line-oriented: '\n' (and the rare '\r')
	// embedded in an argument would terminate the command early and turn
	// the tail into a second, injected command. We have to escape those in
	// addition to '\' and '"'.
	std::string out;
	const char* s = value.String();
	for (size_t i = 0; s[i] != '\0'; i++) {
		char c = s[i];
		switch (c) {
			case '\\':
			case '"':
				out += '\\';
				out += c;
				break;
			case '\n':
				out += '\\';
				out += 'n';
				break;
			case '\r':
				out += '\\';
				out += 'r';
				break;
			default:
				out += c;
				break;
		}
	}
	return out;
}


// Synchronously run `ifconfig <args...>` (where the variadic list ends in a
// trailing NULL) and wait for it to finish. Returns true on a zero exit
// status. Errors are logged to stderr but don't otherwise propagate -- the
// caller decides whether to surface them as a connection-level error. When
// `quiet` is true the child's stderr is redirected to /dev/null, which is
// what the slot-picking probe wants: tun/N being missing or in a stuck
// state is an expected outcome there, not a problem to surface.
static bool
run_ifconfig(const char* const argv[], bool quiet = false)
{
	pid_t pid = -1;
	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_t* actionsPtr = NULL;
	if (quiet) {
		if (posix_spawn_file_actions_init(&actions) == 0
			&& posix_spawn_file_actions_addopen(&actions, STDERR_FILENO,
				"/dev/null", O_WRONLY, 0) == 0) {
			actionsPtr = &actions;
		}
	}

	int rc = posix_spawnp(&pid, "ifconfig", actionsPtr, NULL,
		(char* const*)argv, environ);
	if (actionsPtr != NULL)
		posix_spawn_file_actions_destroy(actionsPtr);

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
// Haiku. Returns false (and complains to stderr) if route exited non-zero,
// because silent failures here are exactly what lets the system end up
// stuck without a working default route.
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

	pid_t pid = -1;
	int rc = posix_spawnp(&pid, "route", NULL, NULL,
		(char* const*)argv, environ);
	if (rc != 0) {
		fprintf(stderr, "%s [spawn failed: %s]\n",
			line.String(), strerror(rc));
		return false;
	}
	int status = 0;
	if (waitpid(pid, &status, 0) != pid) {
		fprintf(stderr, "%s [waitpid failed]\n", line.String());
		return false;
	}
	bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	if (ok) {
		printf("%s\n", line.String());
	} else {
		fprintf(stderr, "%s [exit %d]\n", line.String(),
			WIFEXITED(status) ? WEXITSTATUS(status) : -1);
	}
	return ok;
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
	fInstalledTunPeer(),
	fRoutesInstalled(false),
	fTunInterface(),
	fTunNode(),
	fManagement(),
	fPid(-1),
	fSocket(-1),
	fStderrFd(-1),
	fMgmtPort(0),
	fReader(-1),
	fStderrReader(-1),
	fStopRequested(false),
	fMgmtPoll(NULL),
	fMgmtAttempt(0)
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

	// Take ownership of the "we're connecting" status BEFORE we do any
	// blocking work below. The check above is not an atomic test-and-set,
	// so a second Connect() arriving while we're still spawning would
	// otherwise sail past it and start a second openvpn process whose
	// pid would overwrite ours -- leaving the first openvpn unreapable.
	// _SetState here also pushes "Connecting" to subscribers immediately
	// instead of after the spawn finishes.
	_SetState(VPN_STATE_CONNECTING);

	printf("[OpenVPN] connect requested: profile='%s' config='%s'\n",
		fProfile.fName.String(), fProfile.fConfigPath.String());

	// Haiku publishes tunnel character devices at /dev/tun/N. ifconfig <name>
	// up publishes that device through the kernel add-on. A previous session
	// can leave a slot in a stuck state where ifconfig refuses to re-add it
	// ("General system error"), so we delete first (idempotent: succeeds even
	// if the slot wasn't there) and only then bring it up. We scan upward
	// until we find a slot that takes, in case multiple slots are stuck.
	//
	// Note: we deliberately do NOT pre-assign an address (e.g. 0.0.0.0)
	// before openvpn starts. With --dev-node /dev/tun/N openvpn opens the
	// device very early; if the interface already has an address bound to
	// it, that open blocks on Haiku and openvpn goes silent forever after
	// `hold release`. Plain `up` works.
	fTunInterface = "";
	fTunNode = "";
	for (int slot = 0; slot < 8; slot++) {
		BString interfaceName;
		interfaceName << "tun/" << slot;

		// Quiet mode for the probe: an "Invalid Argument" on --delete
		// just means the slot wasn't in the interface list, and a
		// "General system error" on up means the kernel left this slot
		// in a stuck state (typically after a kill -9 of openvpn) and
		// only a reboot will free it. Both are expected outcomes of the
		// probe; logging them as ifconfig errors makes a clean startup
		// look broken.
		const char* const ifconfigDelete[] = {
			"ifconfig", "--delete", interfaceName.String(), NULL
		};
		run_ifconfig(ifconfigDelete, /*quiet=*/true);

		const char* const ifconfigUp[] = {
			"ifconfig", interfaceName.String(), "up", NULL
		};
		if (run_ifconfig(ifconfigUp, /*quiet=*/true)) {
			fTunInterface = interfaceName;
			fTunNode = "";
			fTunNode << "/dev/tun/" << slot;
			printf("[OpenVPN] using %s (%s)\n",
				fTunInterface.String(), fTunNode.String());
			break;
		}
		printf("[OpenVPN] %s is stuck (kernel-side); trying next slot\n",
			interfaceName.String());
	}
	if (fTunInterface.Length() == 0) {
		_SetState(VPN_STATE_ERROR,
			"no usable tun slot (every /dev/tun/N is stuck; reboot needed?)");
		return B_ERROR;
	}

	if (!_SpawnOpenVPN(fProfile)) {
		_SetState(VPN_STATE_ERROR,
			"could not start openvpn (is it installed?)");
		return B_ERROR;
	}

	// Start the stderr-reader BEFORE the management connect. If openvpn
	// refuses to start (bad --dev-node, bad .ovpn, missing cert, anything
	// printed to stderr before it opens the management socket), we'd
	// otherwise close the pipe in _Cleanup() and lose the actual reason --
	// the user would only see "could not reach openvpn management port".
	_StartStderrReader();

	// Connect to openvpn's management socket asynchronously. openvpn opens
	// the listen socket shortly after we return from posix_spawnp, so we
	// poll for it. Running this as a looper-driven poll (rather than a
	// blocking retry loop that pins the looper for up to 5s) keeps the
	// daemon answering GetStatus/Disconnect/other clients during the connect,
	// and -- crucially -- lets a Disconnect() arriving mid-connect actually
	// cancel it. The rest of the handshake happens in _OnMgmtConnected once
	// the socket is up.
	_BeginMgmtConnect();
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
	BAutolock guard(fCredentialsLock);
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

		case kMsgTryMgmtConnect:
			_TryMgmtConnect();
			break;

		case kMsgReaderExited:
			// The reader is gone; tear the rest down and report Disconnected
			// (unless we already landed on ERROR from a FATAL/AUTH_FAILED).
			_Cleanup(true);
			if (fState != VPN_STATE_ERROR)
				_SetState(VPN_STATE_DISCONNECTED);
			break;

		// kMsgLogLine is no longer dispatched: the stderr reader scans and
		// echoes log lines on its own thread (see _RunStderrLoop). Kept out
		// of the switch deliberately so a stray message routes to the
		// default branch and gets logged.

		default:
			VPNBackend::MessageReceived(message);
			break;
	}
}


// --- lifecycle -------------------------------------------------------------

bool
OpenVPNBackend::_CreateMgmtPasswordFile()
{
	// 32 hex chars of entropy is plenty for a one-shot local secret.
	char token[33];
	for (int i = 0; i < 32; i++) {
		// Mix two rand() calls and a thread id so that a recently re-seeded
		// rand on an attacker process can't replay last second's token.
		unsigned mixed = (unsigned)rand() ^ (unsigned)(rand() << 4)
			^ (unsigned)find_thread(NULL) ^ (unsigned)system_time();
		token[i] = "0123456789abcdef"[mixed & 0xf];
	}
	token[32] = '\0';
	fMgmtPassword = token;

	// mkstemp() picks a unique name AND opens the fd 0600, which avoids the
	// classic "predictable temp name" race. We write the token + newline
	// (openvpn requires the trailing \n) and unlink on _Cleanup().
	char path[] = "/tmp/sotoportego.mgmtXXXXXX";
	int fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "[OpenVPN] mkstemp failed: %s\n", strerror(errno));
		fMgmtPassword = "";
		return false;
	}
	std::string line(token);
	line.push_back('\n');
	ssize_t wrote = write(fd, line.data(), line.size());
	close(fd);
	if (wrote != (ssize_t)line.size()) {
		unlink(path);
		fMgmtPassword = "";
		return false;
	}
	fMgmtPasswordFile = path;
	return true;
}


void
OpenVPNBackend::_RemoveMgmtPasswordFile()
{
	if (fMgmtPasswordFile.Length() > 0) {
		unlink(fMgmtPasswordFile.String());
		fMgmtPasswordFile = "";
	}
	fMgmtPassword = "";
}


bool
OpenVPNBackend::_SpawnOpenVPN(const VPNProfile& profile)
{
	// Pick a port now so the same string can go into the argv. A real
	// collision is rare and surfaces as a connect failure below.
	fMgmtPort = kMgmtPortBase + (rand() % kMgmtPortSpread);
	char portStr[16];
	snprintf(portStr, sizeof(portStr), "%d", fMgmtPort);

	// Random per-session password gating the management socket. Without
	// this any local process can connect to 127.0.0.1:<fMgmtPort> and drive
	// openvpn (signal SIGTERM, swap our credentials, read tunnel events).
	if (!_CreateMgmtPasswordFile()) {
		fprintf(stderr,
			"[OpenVPN] could not write management password file\n");
		return false;
	}

	// Build argv. posix_spawnp wants char*; the strings live for the
	// duration of the call only, so casting away const here is fine.
	//
	// --management ... <pwfile> tells openvpn to read the first line of
	// pwfile and require it as the first command on the socket -- so the
	// daemon's first send is the password, NOT 'state on'.
	//
	// --route-noexec keeps openvpn out of the routing table; the Haiku
	// port adds every pushed route on the underlying physical interface
	// (e.g. wifi) instead of on the tun slot, so redirect-gateway routes
	// land on wifi and tunnel traffic disappears. _InstallRoutes()
	// re-applies the right routes once CONNECTED arrives and
	// _ScanLogLine has captured ROUTE_GATEWAY + PUSH_REPLY from the
	// child's stderr.
	//
	// --ifconfig-noexec keeps openvpn from re-running ifconfig on the
	// tunnel device; we already brought the slot up ourselves in
	// Connect() and we re-issue ifconfig with the pushed local/peer IPs
	// in _HandleManagementEvent when CONNECTED arrives.
	// --dev-node points openvpn at the character device the Haiku tunnel
	// add-on publishes when we did `ifconfig tun/N up` above. Without it
	// open_tun() falls back to the BSD-style dynamic guess ("/dev/tun0",
	// "/dev/tun1", ...), none of which exist on Haiku (the path has a slash:
	// /dev/tun/N), and openvpn dies with "Cannot allocate TUN/TAP dev
	// dynamically" before its management socket is even open.
	char* argv[] = {
		(char*)"openvpn",
		(char*)"--config", (char*)profile.fConfigPath.String(),
		(char*)"--dev-node", (char*)fTunNode.String(),
		(char*)"--management", (char*)"127.0.0.1", portStr,
			(char*)fMgmtPasswordFile.String(),
		(char*)"--management-hold",
		(char*)"--management-query-passwords",
		(char*)"--route-noexec",
		(char*)"--ifconfig-noexec",
		// Cap the TCP MSS so each tunnelled segment fits comfortably
		// inside the carrier link's MTU after our own header overhead.
		// Without this Haiku's TCP stack returns partial sends from
		// time to time (`TCP/UDP packet was truncated/expanded on
		// write`), which openvpn treats as a fatal error and triggers
		// a soft restart -- the symptom is a session that drops every
		// few minutes when the Wi-Fi is even mildly stressed. 1300
		// leaves headroom for 60 bytes of TCP/IP plus our tunnel
		// framing on a standard 1500-byte path.
		(char*)"--mssfix", (char*)"1300",
		(char*)"--verb", (char*)"3",
		NULL
	};

	// We used to fork()+execvp() so the child could close every inherited
	// descriptor by hand, because the BApplication leaves a non-trivial
	// number of internal fds open and at least one of them stalls openvpn
	// right after `hold release`. The fork worked but broke time(2) inside
	// the child: openvpn ended up timestamping its log lines (and verifying
	// TLS certs) at epoch 1230768399 -- 2009-01-01 -- which made every
	// modern Let's Encrypt-signed peer cert look "not yet valid".
	//
	// The fix is to never inherit those fds in the first place: every long
	// lived fd we open (management socket, log pipe read end, any other
	// helper) gets FD_CLOEXEC, the log pipe write end is duped onto BOTH
	// STDOUT_FILENO and STDERR_FILENO via posix_spawn_file_actions, and we
	// can drop the fork in favour of posix_spawnp() again. No fork from a
	// multi-threaded BApp = no broken time in the child.
	//
	// IMPORTANT: openvpn's timestamped log lines (`ROUTE_GATEWAY`,
	// `PUSH_REPLY`, the version banner, ...) go to STDOUT, not stderr --
	// so we *must* capture stdout, otherwise _ScanLogLine never sees the
	// values it needs for the route fix-up. Stderr only ever gets the
	// option-parse errors. We pipe both onto the same fd so the reader
	// thread doesn't have to multiplex two streams.
	int logPipe[2];
	if (pipe(logPipe) != 0) {
		fprintf(stderr, "[OpenVPN] pipe failed: %s\n", strerror(errno));
		return false;
	}
	// Read end stays in the parent only; we keep it FD_CLOEXEC so the next
	// posix_spawn doesn't leak it. The write end is intentionally NOT
	// FD_CLOEXEC: the file_actions below dup it onto the child's stdio
	// fds and then close the original write fd.
	fcntl(logPipe[0], F_SETFD, FD_CLOEXEC);

	posix_spawn_file_actions_t actions;
	if (posix_spawn_file_actions_init(&actions) != 0) {
		close(logPipe[0]);
		close(logPipe[1]);
		return false;
	}
	// Send openvpn's stdin to /dev/null so it never tries to read from the
	// daemon's terminal; route both stdout and stderr onto our pipe.
	posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null",
		O_RDONLY, 0);
	posix_spawn_file_actions_adddup2(&actions, logPipe[1], STDOUT_FILENO);
	posix_spawn_file_actions_adddup2(&actions, logPipe[1], STDERR_FILENO);
	posix_spawn_file_actions_addclose(&actions, logPipe[1]);

	pid_t pid = -1;
	int rc = posix_spawnp(&pid, "openvpn", &actions, NULL, argv, environ);
	posix_spawn_file_actions_destroy(&actions);

	if (rc != 0) {
		fprintf(stderr, "[OpenVPN] posix_spawnp failed: %s\n", strerror(rc));
		close(logPipe[0]);
		close(logPipe[1]);
		return false;
	}

	// Parent: drop the write end so the read end sees EOF when openvpn
	// exits; keep the read end for the log-reader thread.
	close(logPipe[1]);
	fStderrFd = logPipe[0];

	fPid = pid;
	printf("[OpenVPN] spawned openvpn pid=%d mgmt=127.0.0.1:%d\n",
		(int)fPid, fMgmtPort);
	return true;
}


void
OpenVPNBackend::_BeginMgmtConnect()
{
	fMgmtAttempt = 0;
	_StopMgmtPoll();

	// A repeating runner drives one probe every kMgmtConnectInterval; the
	// handler stops it on success, failure, or cancel. All ticks land on the
	// looper, so the whole connect sequence stays single-threaded -- no locks
	// on fSocket/fPid/fState, matching the rest of the backend.
	BMessage tick(kMsgTryMgmtConnect);
	fMgmtPoll = new BMessageRunner(BMessenger(this), &tick, kMgmtConnectInterval);
	if (fMgmtPoll == NULL || fMgmtPoll->InitCheck() != B_OK) {
		_StopMgmtPoll();
		_Cleanup(true);
		_SetState(VPN_STATE_ERROR, "could not start management poll");
		return;
	}

	// Fire the first probe now rather than waiting a full interval; the runner
	// covers every retry after that. PostMessage keeps it on the looper thread.
	if (Looper() != NULL)
		Looper()->PostMessage(kMsgTryMgmtConnect, this);
}


void
OpenVPNBackend::_TryMgmtConnect()
{
	// A tick can still be queued after we already stopped the runner (deleting
	// a BMessageRunner doesn't unsend an in-flight message); ignore stragglers.
	if (fMgmtPoll == NULL)
		return;

	// Disconnect() landed between probes. This is the cancellation the old
	// blocking loop could never honour: back then the looper was stuck inside
	// Connect() and could not dispatch Disconnect at all.
	if (fStopRequested) {
		_StopMgmtPoll();
		_Cleanup(true);
		_SetState(VPN_STATE_DISCONNECTED, "cancelled");
		return;
	}

	// openvpn died before its management socket came up (bad --dev-node, bad
	// .ovpn, missing cert, exec failure). exit=127 means execvp failed; a
	// signal usually means a crash. The stderr reader has already echoed the
	// real reason on its own thread.
	int status = 0;
	pid_t reaped = waitpid(fPid, &status, WNOHANG);
	if (reaped == fPid) {
		if (WIFEXITED(status)) {
			int code = WEXITSTATUS(status);
			fprintf(stderr,
				"[OpenVPN] child exited before management was ready "
				"(exit=%d%s)\n", code,
				code == 127 ? "; openvpn binary not found?" : "");
		} else if (WIFSIGNALED(status)) {
			fprintf(stderr,
				"[OpenVPN] child exited before management was ready "
				"(killed by signal %d)\n", WTERMSIG(status));
		} else {
			fprintf(stderr,
				"[OpenVPN] child exited before management was ready "
				"(status=0x%x)\n", status);
		}
		fPid = -1;
		_StopMgmtPoll();
		_Cleanup(true);
		_SetState(VPN_STATE_ERROR, "openvpn exited before management was ready");
		return;
	}

	// One non-blocking probe. On loopback a not-yet-listening port fails fast
	// with ECONNREFUSED, so this never stalls the looper.
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd >= 0) {
		// Keep this fd out of every subsequent posix_spawn we do; otherwise a
		// child like `route` or `ifconfig` could inherit a live socket to the
		// management interface.
		fcntl(fd, F_SETFD, FD_CLOEXEC);

		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(fMgmtPort);
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
			fSocket = fd;
			_StopMgmtPoll();
			_OnMgmtConnected();
			return;
		}
		close(fd);
	}

	if (++fMgmtAttempt >= kMgmtConnectAttempts) {
		_StopMgmtPoll();
		_Cleanup(true);
		_SetState(VPN_STATE_ERROR, "could not reach openvpn management port");
	}
	// Otherwise the runner fires again after kMgmtConnectInterval.
}


void
OpenVPNBackend::_OnMgmtConnected()
{
	// FIRST line on the socket MUST be the random session password from the
	// file we passed via `--management ... <pwfile>`. openvpn closes the
	// connection on any other first input. This is what stops a local process
	// that races us to 127.0.0.1:<fMgmtPort> from driving the tunnel (signal
	// SIGTERM, sniff credentials, swap state).
	_SendCommand(fMgmtPassword.String());

	// Subscribe to state and throughput, then let openvpn move past the
	// management-hold gate. ROUTE_GATEWAY and PUSH_REPLY -- the values
	// _ScanLogLine needs for the route fix-up -- are NOT collected via
	// `log on` (it deadlocks openvpn on Haiku right after `hold release`)
	// but via the stderr pipe wired up by _StartStderrReader().
	//
	// openvpn 2.6 on Haiku, with --management-query-passwords in play, can
	// re-enter the management hold AFTER the first release (the management
	// log shows "SUCCESS: hold release succeeded" immediately followed by
	// a fresh ">HOLD:Waiting for hold release:0"). `hold off` sets the
	// "no more holds" flag but doesn't release any in-flight one; the reader
	// loop catches each >HOLD: and replies with `hold release`, so the
	// connection keeps moving.
	_SendCommand("state on");
	_SendCommand("bytecount 1");
	_SendCommand("hold off");
	_SendCommand("hold release");

	_StartReader();
}


void
OpenVPNBackend::_StopMgmtPoll()
{
	delete fMgmtPoll;
	fMgmtPoll = NULL;
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


void
OpenVPNBackend::_StartStderrReader()
{
	if (fStderrFd < 0)
		return;
	fStderrReader = spawn_thread(_StderrReaderEntry, "openvpn-stderr",
		B_NORMAL_PRIORITY, this);
	if (fStderrReader < B_OK) {
		fprintf(stderr, "[OpenVPN] spawn_thread (stderr) failed\n");
		fStderrReader = -1;
		return;
	}
	resume_thread(fStderrReader);
}


int32
OpenVPNBackend::_ReaderEntry(void* self)
{
	return ((OpenVPNBackend*)self)->_RunReaderLoop();
}


int32
OpenVPNBackend::_StderrReaderEntry(void* self)
{
	return ((OpenVPNBackend*)self)->_RunStderrLoop();
}


int32
OpenVPNBackend::_RunStderrLoop()
{
	// Each line is handled entirely on this thread:
	//   * echoed to the daemon's stderr so the log is visible even when
	//     the looper is busy in Connect() (a fast openvpn crash would
	//     otherwise look like a bare "child exited" with no reason);
	//   * fed to _ScanLogLine, which behind fScanLock harvests
	//     ROUTE_GATEWAY / PUSH_REPLY for the route fix-up.
	// Crucially we do NOT round-trip through the looper for this: while
	// Connect() is running on the looper, the management reader can race
	// us with a CONNECTED event that arrives at the looper queue before
	// our log lines do, and _InstallRoutes would then see empty fields.
	char buffer[kReaderBufferSize];
	std::string line;
	while (true) {
		ssize_t got = read(fStderrFd, buffer, sizeof(buffer));
		if (got < 0 && errno == EINTR)
			continue;
		if (got <= 0)
			break;
		for (ssize_t i = 0; i < got; i++) {
			char c = buffer[i];
			if (c == '\n') {
				if (!line.empty()) {
					fprintf(stderr, "[OpenVPN] %s\n", line.c_str());
					fflush(stderr);
					_ScanLogLine(line);
				}
				line.clear();
			} else if (c != '\r') {
				line += c;
			}
		}
	}
	// openvpn occasionally dies without flushing a trailing newline; print
	// whatever we collected so the reason isn't lost.
	if (!line.empty()) {
		fprintf(stderr, "[OpenVPN] %s\n", line.c_str());
		fflush(stderr);
		_ScanLogLine(line);
	}
	return B_OK;
}


int32
OpenVPNBackend::_RunReaderLoop()
{
	char buffer[kReaderBufferSize];
	while (true) {
		ssize_t got = recv(fSocket, buffer, sizeof(buffer), 0);
		if (got < 0 && errno == EINTR) {
			// A signal interrupted the syscall; keep listening.
			continue;
		}
		if (got <= 0)
			break;

		std::string chunk(buffer, (size_t)got);
		std::vector<OpenVPNEvent> events = fManagement.Feed(chunk);
		for (size_t i = 0; i < events.size(); i++) {
			// Credentials and hold-release are answered right here on the
			// I/O thread so we stay responsive to openvpn's prompts;
			// everything else gets dispatched to the looper.
			const OpenVPNEvent& event = events[i];
			if (event.type == OPENVPN_EVENT_PASSWORD_REQUEST) {
				// Snapshot the credentials under the lock -- SetCredentials()
				// / _Cleanup() can rewrite these BStrings from the looper
				// thread, and a BString read racing a write is unsafe.
				BString user, pass;
				{
					BAutolock guard(fCredentialsLock);
					user = fAuthUsername;
					pass = fAuthPassword;
				}
				if (user.Length() > 0) {
					char line[1024];
					snprintf(line, sizeof(line), "username \"%s\" \"%s\"",
						event.realm.c_str(), escape_arg(user).c_str());
					_SendCommand(line);
					snprintf(line, sizeof(line), "password \"%s\" \"%s\"",
						event.realm.c_str(), escape_arg(pass).c_str());
					_SendCommand(line);
				}
			} else if (event.type == OPENVPN_EVENT_HOLD) {
				// We already sent `hold off` at startup, so we should not
				// normally see this. If openvpn does emit a hold (some
				// reconnect paths can), release it -- otherwise the daemon
				// would sit waiting for a release that never comes.
				_SendCommand("hold release");
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
	// Cancel any in-flight management-connect poll first, so a straggling
	// tick can't fire a second teardown or spawn a reader after we're gone.
	_StopMgmtPoll();

	if (fSocket >= 0) {
		// Closing kicks any blocked recv() in the reader thread, if it is
		// still alive.
		shutdown(fSocket, SHUT_RDWR);
		close(fSocket);
		fSocket = -1;
	}

	if (fStderrFd >= 0) {
		// Closing makes the stderr-reader's read() return 0 next iteration
		// so the thread can exit without us having to send it a signal.
		close(fStderrFd);
		fStderrFd = -1;
	}

	if (fReader > 0 && wait) {
		status_t exitCode = 0;
		wait_for_thread(fReader, &exitCode);
		fReader = -1;
	}

	if (fStderrReader > 0 && wait) {
		status_t exitCode = 0;
		wait_for_thread(fStderrReader, &exitCode);
		fStderrReader = -1;
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

	// Tear the tun slot we used out of the interface list entirely.
	// `ifconfig <iface> down` only deactivates it -- the interface stays
	// around with whatever IP openvpn pushed onto it, and the next Connect
	// would inherit a stale address. `--delete` removes the interface; the
	// kernel tunnel add-on republishes it next time we ifconfig it up.
	if (fTunInterface.Length() > 0) {
		const char* const ifconfigDelete[] = {
			"ifconfig", "--delete", fTunInterface.String(), NULL
		};
		run_ifconfig(ifconfigDelete);
	}

	fLocalIP = "";
	{
		BAutolock guard(fCredentialsLock);
		fAuthUsername = "";
		fAuthPassword = "";
	}
	// Clearing the harvest fields races with the stderr-reader thread on
	// every reconnect; take fScanLock so a stale line in flight doesn't
	// land in the next session.
	{
		BAutolock guard(fScanLock);
		fOrigGateway = "";
		fOrigGatewayIface = "";
		fTunPeer = "";
	}
	fTunInterface = "";
	fTunNode = "";
	_RemoveMgmtPasswordFile();
}


// --- protocol --------------------------------------------------------------

void
OpenVPNBackend::_SendCommand(const char* line)
{
	if (line == NULL)
		return;

	// Serialize with any concurrent send from the other thread: _SendCommand
	// is called from both the looper (Disconnect, _OnMgmtConnected) and the
	// reader thread (answering >PASSWORD/>HOLD), and two interleaved sends
	// would splice two commands into one corrupt line.
	BAutolock guard(fSendLock);
	if (fSocket < 0)
		return;

	// Build the framed line once so a partial send can be resumed from the
	// right offset. Management is line-oriented: if we only send half, the
	// remote interprets a corrupted command and we lose protocol sync.
	size_t length = strlen(line);
	std::string framed;
	framed.reserve(length + 1);
	framed.append(line, length);
	framed.push_back('\n');

	const char* data = framed.data();
	size_t remaining = framed.size();
	while (remaining > 0) {
		// MSG_NOSIGNAL stops a broken pipe from killing the whole daemon
		// when openvpn disappears mid-write; the EPIPE return is enough.
		ssize_t wrote = send(fSocket, data, remaining, MSG_NOSIGNAL);
		if (wrote > 0) {
			data += wrote;
			remaining -= (size_t)wrote;
			continue;
		}
		if (wrote < 0 && errno == EINTR)
			continue;
		// Any other error (EPIPE, ECONNRESET, EBADF, ...) means the socket
		// is gone; the reader thread will see EOF and unwind.
		break;
	}
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
				// Snapshot the values harvested off the stderr stream
				// behind fScanLock so we read a coherent picture even if
				// the stderr reader is still in the middle of writing
				// them. Reading via the lock guarantees we either see
				// nothing (empty Strings) or the fully assigned values --
				// never a torn copy.
				BString tunPeerSnapshot;
				{
					BAutolock guard(fScanLock);
					tunPeerSnapshot = fTunPeer;
				}
				// The Haiku openvpn port runs `/bin/ifconfig tun inet
				// <ip> <peer> ...` itself, but it passes the unqualified
				// "tun" name and ifconfig rejects it with "No such
				// device". --ifconfig-noexec keeps openvpn out of our
				// way; we do the call here with the slot we actually
				// own. fTunPeer comes from the PUSH_REPLY's
				// route-gateway, captured by _ScanLogLine.
				if (fTunInterface.Length() > 0 && fLocalIP.Length() > 0
						&& tunPeerSnapshot.Length() > 0) {
					const char* const ifconfigUp[] = {
						"ifconfig", fTunInterface.String(), "inet",
						fLocalIP.String(), tunPeerSnapshot.String(),
						"mtu", "1500", "up", NULL
					};
					run_ifconfig(ifconfigUp);
				}
				// All the values needed for the route fix-up have been
				// scanned out of the preceding log lines (ROUTE_GATEWAY
				// and PUSH_REPLY). event.remoteIP is the VPN server's
				// public IP, the third piece we need.
				if (fRoutesInstalled) {
					// This is a CONNECTED arriving after a soft restart
					// (ping-restart -> reconnect): the routes are still
					// in place but they aim at the previous tunnel
					// peer. Swap just the default route to the new one.
					_RefreshTunRoute();
				} else {
					_InstallRoutes(BString(event.remoteIP.c_str()));
				}
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
	// Called from BOTH the stderr-reader thread (per-line, before any of it
	// reaches the looper) AND the looper itself when a >LOG:... shows up on
	// the management socket. fScanLock is what keeps those two paths from
	// stepping on the BString assignments below; the CONNECTED handler on
	// the looper takes the same lock to snapshot the harvested values.
	BAutolock guard(fScanLock);

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
	//
	// We update on EVERY PUSH_REPLY, not just the first one: when
	// openvpn does a soft restart (e.g. ping-restart fires) the server
	// hands out a fresh tunnel peer. Without this update the route
	// fix-up below would happily keep aiming the default route at the
	// dead peer from the previous session, the keepalives never reach
	// the server, ping-restart fires again, and we'd be stuck in a
	// reconnect loop until something timed out for real.
	{
		size_t pos = line.find("route-gateway ");
		if (pos != std::string::npos) {
			std::string peer = take_token(line, pos + 14);
			if (!peer.empty() && BString(peer.c_str()) != fTunPeer) {
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

	// Snapshot the values harvested off the stderr stream behind
	// fScanLock. We make local copies so the rest of this routine -- with
	// its many run_route() calls -- can stay outside the lock.
	BString origGateway;
	BString origGatewayIface;
	BString tunPeer;
	{
		BAutolock guard(fScanLock);
		origGateway = fOrigGateway;
		origGatewayIface = fOrigGatewayIface;
		tunPeer = fTunPeer;
	}

	// All three values are needed -- without them we can't even guess at the
	// right route commands, so refuse rather than do something destructive.
	if (origGateway.Length() == 0 || origGatewayIface.Length() == 0
			|| tunPeer.Length() == 0 || vpnServerIP.Length() == 0) {
		fprintf(stderr,
			"[OpenVPN] missing routing info, skipping route fix-up "
			"(server=%s gw=%s iface=%s peer=%s)\n",
			vpnServerIP.String(),
			origGateway.String(),
			origGatewayIface.String(),
			tunPeer.String());
		return;
	}

	// 1) Pin the VPN server to the underlying default route so openvpn's
	// UDP/TCP packets don't try to flow back through the tunnel they're
	// carrying.
	const char* const serverPin[] = {
		"route", "add", origGatewayIface.String(), "inet",
		vpnServerIP.String(), "gw", origGateway.String(),
		"netmask", "255.255.255.255", NULL
	};
	run_route(serverPin);

	// 2) Drop the existing default route. We originally installed two /1
	// halves on top of the wifi /0 hoping longest-prefix match would do
	// the right thing, but Haiku's routing keeps preferring the /0 and
	// traffic stays on wifi -- verified with `ping 8.8.8.8` returning a
	// local-LAN-speed latency while the tunnel was up. The only reliable
	// pattern is to replace the default outright.
	const char* const dropDefault[] = {
		"route", "delete", origGatewayIface.String(), "inet", "0.0.0.0",
		"gw", origGateway.String(), "netmask", "0.0.0.0", NULL
	};
	run_route(dropDefault);

	// 3) Install our own default route pointing at the tunnel peer.
	const char* const addDefault[] = {
		"route", "add", fTunInterface.String(), "inet", "0.0.0.0",
		"gw", tunPeer.String(), "netmask", "0.0.0.0", NULL
	};
	run_route(addDefault);

	fInstalledServerIP = vpnServerIP;
	fInstalledTunPeer = tunPeer;
	fRoutesInstalled = true;

	// Persist the values _ApplyRestore would need so a crashed daemon can
	// undo this on its next launch. Best-effort: a failed write is logged
	// but doesn't stop the connection from coming up.
	_WriteSessionFile();
}


void
OpenVPNBackend::_RefreshTunRoute()
{
	// Called from the CONNECTED handler when fRoutesInstalled is already
	// true (i.e. openvpn did a soft restart). The VPN server's public IP
	// and the carrier-side default route haven't changed, but the tunnel
	// peer the server hands out CAN: when that happens the kernel route
	// still points at the dead peer from the previous session and no
	// traffic flows -- the symptom the user sees is a perpetual
	// ping-restart loop.
	BString newPeer;
	{
		BAutolock guard(fScanLock);
		newPeer = fTunPeer;
	}
	if (newPeer.Length() == 0 || newPeer == fInstalledTunPeer)
		return;

	const char* const dropOld[] = {
		"route", "delete", fTunInterface.String(), "inet", "0.0.0.0",
		"gw", fInstalledTunPeer.String(), "netmask", "0.0.0.0", NULL
	};
	run_route(dropOld);

	const char* const addNew[] = {
		"route", "add", fTunInterface.String(), "inet", "0.0.0.0",
		"gw", newPeer.String(), "netmask", "0.0.0.0", NULL
	};
	run_route(addNew);

	printf("[OpenVPN] tunnel peer changed on reconnect: %s -> %s\n",
		fInstalledTunPeer.String(), newPeer.String());
	fInstalledTunPeer = newPeer;
	_WriteSessionFile();
}


void
OpenVPNBackend::_RemoveRoutes()
{
	if (!fRoutesInstalled)
		return;
	// Tear the default route down via the peer we ACTUALLY installed it
	// for, not via fTunPeer -- on a soft reconnect those two diverge,
	// and using fTunPeer here would call `route delete ... gw <new>`
	// which doesn't match the kernel's stored route and leaves the old
	// default in place.
	_ApplyRestore(fTunInterface, fInstalledTunPeer, fOrigGateway,
		fOrigGatewayIface, fInstalledServerIP);
	fRoutesInstalled = false;
	_RemoveSessionFile();
	fInstalledServerIP = "";
	fInstalledTunPeer = "";
}


void
OpenVPNBackend::_ApplyRestore(const BString& tunIface, const BString& tunPeer,
	const BString& origGateway, const BString& origGatewayIface,
	const BString& serverIP)
{
	// 1) Drop the default route we installed via the tunnel. We do this
	// first so the kernel doesn't keep sending packets at a dead tun
	// peer while we're still busy putting the original default back.
	if (tunIface.Length() > 0 && tunPeer.Length() > 0) {
		const char* const dropTunDefault[] = {
			"route", "delete", tunIface.String(), "inet", "0.0.0.0",
			"gw", tunPeer.String(), "netmask", "0.0.0.0", NULL
		};
		run_route(dropTunDefault);
	}

	// 2) Re-add the original default route the user had before we touched
	// anything. Without this the box has no internet until DHCP renews or
	// the user manually fixes the route.
	if (origGateway.Length() > 0 && origGatewayIface.Length() > 0) {
		const char* const restoreDefault[] = {
			"route", "add", origGatewayIface.String(), "inet", "0.0.0.0",
			"gw", origGateway.String(), "netmask", "0.0.0.0", NULL
		};
		run_route(restoreDefault);
	}

	// 3) Drop the server pin -- the dedicated /32 we added so openvpn's
	// own control traffic could escape the tunnel.
	if (serverIP.Length() > 0 && origGateway.Length() > 0
			&& origGatewayIface.Length() > 0) {
		const char* const dropPin[] = {
			"route", "delete", origGatewayIface.String(), "inet",
			serverIP.String(), "gw", origGateway.String(),
			"netmask", "255.255.255.255", NULL
		};
		run_route(dropPin);
	}
}


status_t
OpenVPNBackend::_SessionPath(BPath* path)
{
	if (path == NULL)
		return B_BAD_VALUE;
	status_t result = find_directory(B_USER_SETTINGS_DIRECTORY, path);
	if (result != B_OK)
		return result;
	result = path->Append("Sotoportego");
	if (result != B_OK)
		return result;
	result = create_directory(path->Path(), 0755);
	if (result != B_OK)
		return result;
	return path->Append("session");
}


bool
OpenVPNBackend::_WriteSessionFile() const
{
	BPath path;
	if (_SessionPath(&path) != B_OK)
		return false;

	BMessage record;
	record.AddInt32("openvpnPid", (int32)fPid);
	record.AddString("tunInterface", fTunInterface);
	record.AddString("tunPeer", fTunPeer);
	record.AddString("origGateway", fOrigGateway);
	record.AddString("origGatewayIface", fOrigGatewayIface);
	record.AddString("serverIP", fInstalledServerIP);

	BFile file(path.Path(),
		B_WRITE_ONLY | B_CREATE_FILE | B_ERASE_FILE);
	if (file.InitCheck() != B_OK) {
		fprintf(stderr, "[OpenVPN] could not open session file %s: %s\n",
			path.Path(), strerror(file.InitCheck()));
		return false;
	}
	if (record.Flatten(&file) != B_OK) {
		fprintf(stderr, "[OpenVPN] could not flatten session record\n");
		return false;
	}
	return true;
}


void
OpenVPNBackend::_RemoveSessionFile() const
{
	BPath path;
	if (_SessionPath(&path) != B_OK)
		return;
	unlink(path.Path());
}


void
OpenVPNBackend::RecoverIfCrashed()
{
	BPath path;
	if (_SessionPath(&path) != B_OK)
		return;

	BFile file(path.Path(), B_READ_ONLY);
	if (file.InitCheck() == B_ENTRY_NOT_FOUND)
		return;	// no previous session, nothing to do
	if (file.InitCheck() != B_OK) {
		fprintf(stderr, "[server] cannot open session file %s: %s\n",
			path.Path(), strerror(file.InitCheck()));
		return;
	}

	BMessage record;
	if (record.Unflatten(&file) != B_OK) {
		fprintf(stderr,
			"[server] session file %s is corrupt; removing\n", path.Path());
		unlink(path.Path());
		return;
	}

	int32 prevPid = -1;
	BString tunIface, tunPeer, origGateway, origGatewayIface, serverIP;
	record.FindInt32("openvpnPid", &prevPid);
	record.FindString("tunInterface", &tunIface);
	record.FindString("tunPeer", &tunPeer);
	record.FindString("origGateway", &origGateway);
	record.FindString("origGatewayIface", &origGatewayIface);
	record.FindString("serverIP", &serverIP);

	// If openvpn from the previous run is still alive (it can be -- only
	// the daemon supervisor died), terminate it before touching routes:
	// otherwise it would re-add the tunnel default after we restore the
	// underlying one.
	if (prevPid > 0 && kill((pid_t)prevPid, 0) == 0) {
		printf("[server] previous openvpn pid=%d still alive after a "
			"daemon crash; sending SIGTERM\n", (int)prevPid);
		kill((pid_t)prevPid, SIGTERM);
		for (int i = 0; i < 30; i++) {
			if (kill((pid_t)prevPid, 0) != 0)
				break;
			snooze(100000);
		}
		if (kill((pid_t)prevPid, 0) == 0) {
			kill((pid_t)prevPid, SIGKILL);
			waitpid((pid_t)prevPid, NULL, WNOHANG);
		}
	}

	printf("[server] recovering routes from previous crashed session "
		"(tun=%s peer=%s origGw=%s origIface=%s server=%s)\n",
		tunIface.String(), tunPeer.String(), origGateway.String(),
		origGatewayIface.String(), serverIP.String());
	_ApplyRestore(tunIface, tunPeer, origGateway, origGatewayIface, serverIP);

	unlink(path.Path());
}
