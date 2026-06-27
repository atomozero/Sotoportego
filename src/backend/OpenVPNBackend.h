/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef OPENVPN_BACKEND_H
#define OPENVPN_BACKEND_H


#include <sys/types.h>

#include <Locker.h>
#include <OS.h>
#include <String.h>

#include "OpenVPNManagement.h"
#include "VPNBackend.h"

class BPath;


// Real OpenVPN backend.
//
// On Connect() it spawns the `openvpn` binary with `--management 127.0.0.1
// <port> --management-hold --management-query-passwords --config <ovpn>`,
// connects a TCP socket to that management port, and starts a reader thread
// that streams bytes through OpenVPNManagement::Feed(). Every parsed event is
// posted back to the daemon's looper via a private BMessage so all backend
// state mutations happen on the looper thread (no locks).
//
// On Disconnect() it asks openvpn to terminate via `signal SIGTERM` on the
// management socket; the child's exit closes the socket, the reader sees
// EOF, the looper reaps the team and the state machine settles on
// Disconnected.
class OpenVPNBackend : public VPNBackend {
public:
								OpenVPNBackend();
	virtual						~OpenVPNBackend();

	virtual	status_t			Connect(const VPNProfile& profile);
	virtual	status_t			Disconnect();
	virtual	VPNState			State() const;
	virtual	VPNStats			Stats() const;
	virtual	const char*			BackendName() const;
	virtual	BString				LocalIP() const;
	virtual	BString				RemoteIP() const;
	virtual	void				SetCredentials(const BString& user,
									const BString& pass);

	virtual	void				MessageReceived(BMessage* message);

	// Called once during daemon startup, before any Connect(). If the
	// previous run left a session file behind (i.e. daemon or openvpn
	// died with the default route still pointing at a dead tun), tear
	// the broken state down so the user has working internet again. Safe
	// to call when no crash happened: it's a no-op without a session file.
			void				RecoverIfCrashed();

private:
	// --- session file for crash recovery -------------------------------
	// Path: $B_USER_SETTINGS_DIRECTORY/Sotoportego/session
	// Written from _InstallRoutes(); removed from _RemoveRoutes(). The
	// flattened BMessage carries everything _ApplyRestore needs to undo
	// the install, plus the openvpn pid so RecoverIfCrashed() can tell
	// whether the previous run is really dead.
			bool				_WriteSessionFile() const;
			void				_RemoveSessionFile() const;
	static	status_t			_SessionPath(BPath* path);
			void				_ApplyRestore(const BString& tunIface,
									const BString& tunPeer,
									const BString& origGateway,
									const BString& origGatewayIface,
									const BString& serverIP);

	// --- lifecycle -----------------------------------------------------
			bool				_SpawnOpenVPN(const VPNProfile& profile);
			bool				_ConnectManagementSocket();
			void				_StartReader();
			void				_StartStderrReader();
			void				_Cleanup(bool wait);
			int32				_RunReaderLoop();
			int32				_RunStderrLoop();
	static	int32				_ReaderEntry(void* self);
	static	int32				_StderrReaderEntry(void* self);

	// Write a random one-shot password to a temp file so openvpn can
	// authenticate clients to its management interface. Returns the
	// final path on success (also stored in fMgmtPasswordFile) or empty
	// on failure. The file is unlinked from _Cleanup().
			bool				_CreateMgmtPasswordFile();
			void				_RemoveMgmtPasswordFile();

	// --- protocol ------------------------------------------------------
			void				_SendCommand(const char* line);
			void				_PostEvent(const OpenVPNEvent& event);
			void				_HandleManagementEvent(
									const OpenVPNEvent& event);

	// Scan a single openvpn log line for the values our route fix needs:
	// ROUTE_GATEWAY (the original gateway + iface) and PUSH_REPLY's
	// route-gateway (the in-tunnel peer).
			void				_ScanLogLine(const std::string& line);

	// Routing fix-up. The Haiku openvpn port hardcodes rgi->iface for
	// every route it adds, so the pushed default route ends up on the
	// wifi interface and packets disappear. We pass --route-noexec and
	// install the right routes ourselves once the tunnel is up.
			void				_InstallRoutes(const BString& vpnServerIP);
			void				_RemoveRoutes();
	// Update only the default-route target when openvpn soft-restarts
	// the tunnel and the server hands out a new in-tunnel peer.
			void				_RefreshTunRoute();

			void				_SetState(VPNState state,
									const char* detail = NULL);

			VPNState			fState;
			VPNStats			fStats;
			VPNProfile			fProfile;
			BString				fLocalIP;
			BString				fRemoteIP;
			BString				fAuthUsername;
			BString				fAuthPassword;
	// Values harvested from openvpn's log stream and used by _InstallRoutes.
	// `fOrigGatewayIface` is the path the kernel's route command wants
	// (e.g. "/dev/net/iprowifi4965/0"); `fTunPeer` is the in-tunnel peer
	// IP that the pushed default route should target.
	// All three are written from the stderr-reader thread (via
	// _ScanLogLine) and read from the looper thread on CONNECTED, so they
	// live behind fScanLock to keep the two in sync.
			BLocker				fScanLock;
			BString				fOrigGateway;
			BString				fOrigGatewayIface;
			BString				fTunPeer;
			BString				fInstalledServerIP;
	// The tunnel peer the currently-installed default route points at.
	// Distinct from fTunPeer, which always reflects the latest
	// PUSH_REPLY: when openvpn soft-restarts the server hands out a new
	// peer, fTunPeer updates immediately but the kernel route still
	// targets the old one until _RefreshTunRoute swaps them.
			BString				fInstalledTunPeer;
			bool				fRoutesInstalled;
	// Which Haiku tunnel slot we ended up using this session: e.g. "tun/0"
	// for the interface name (passed to ifconfig and route) and "/dev/tun/0"
	// for the device node (passed to openvpn via --dev-node). Picked at
	// Connect() time by scanning for the first free slot, since previous
	// tun/N instances can land in a stuck state that ifconfig refuses to
	// re-add until reboot.
			BString				fTunInterface;
			BString				fTunNode;
			OpenVPNManagement	fManagement;

	// Live process / connection. Owned by Connect()/_Cleanup().
			pid_t				fPid;			// openvpn pid, -1 when none
			int					fSocket;		// management TCP fd, -1 when none
			int					fStderrFd;		// child stderr read end, -1 when none
			int					fMgmtPort;		// chosen at spawn time
			thread_id			fReader;		// -1 when no thread alive
			thread_id			fStderrReader;	// -1 when no thread alive
			bool				fStopRequested;	// true after Disconnect()
	// Random one-shot password the daemon uses to authenticate to the
	// openvpn management socket. Lives in a temp file passed to openvpn
	// via --management; sent as the first line on the socket so any
	// other local process that races us to the port gets disconnected.
			BString				fMgmtPassword;
			BString				fMgmtPasswordFile;
};


#endif	// OPENVPN_BACKEND_H
