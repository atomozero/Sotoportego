/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 *
 * Sotoportego IPC protocol.
 *
 * The daemon (server) owns the VPN lifecycle and is the single source of
 * truth. GUI / Deskbar / CLI clients are untrusted-ish front-ends that talk
 * to the daemon over BMessage. This header defines the message 'what' codes
 * and the BMessage field names that make up that wire protocol, plus the app
 * signatures used to address each binary.
 *
 * Direction conventions below:
 *   C -> S : sent by a client to the server
 *   S -> C : sent by the server to subscribed clients
 */
#ifndef VPN_PROTOCOL_H
#define VPN_PROTOCOL_H


// --- Application signatures ------------------------------------------------

#define kServerSignature	"application/x-vnd.VePro-SotoportegoServer"
#define kCLISignature		"application/x-vnd.VePro-SotoportegoCLI"
// The GUI and Deskbar replicant arrive in a later milestone:
#define kGUISignature		"application/x-vnd.VePro-Sotoportego"


// --- Message 'what' codes --------------------------------------------------

enum {
	// C -> S : connect using the VPNProfile archived under kFieldProfile.
	kMsgConnect			= 'sCon',

	// C -> S : tear down the current connection.
	kMsgDisconnect		= 'sDis',

	// C -> S : request a one-shot status reply (kMsgStatusUpdate) addressed
	// back to the sender (via kFieldClient, or the message's reply address).
	kMsgGetStatus		= 'sGst',

	// C -> S : register the BMessenger in kFieldClient to receive future
	// broadcasts. Idempotent.
	kMsgSubscribe		= 'sSub',

	// C -> S : stop receiving broadcasts.
	kMsgUnsubscribe		= 'sUns',

	// S -> C : the VPN state changed (or a reply to kMsgGetStatus). Carries
	// kFieldState, optionally kFieldDetail and the kField* stats values.
	kMsgStatusUpdate	= 'sUpd',

	// S -> C : periodic throughput update. Carries the kField* stats values.
	kMsgStatsUpdate		= 'sStt',

	// C -> S : add or update a profile in the daemon's profile store. The
	// payload is an archived VPNProfile under kFieldProfile. Keyed by name:
	// saving a profile whose name matches an existing one overwrites it.
	kMsgSaveProfile		= 'sSav',

	// C -> S : remove a profile by name (kFieldProfileName).
	kMsgDeleteProfile	= 'sDel',

	// S -> C : the current profile list, broadcast on subscribe and whenever
	// it changes. Each archived profile is added under kFieldProfile.
	kMsgListProfiles	= 'sLst'
};


// --- BMessage field names --------------------------------------------------

// VPNState as int32.
static const char* const kFieldState		= "soto:state";
// Human-readable detail / error string.
static const char* const kFieldDetail		= "soto:detail";
// Archived VPNProfile (a nested BMessage).
static const char* const kFieldProfile		= "soto:profile";
// BMessenger identifying a client (for subscribe / targeted replies).
static const char* const kFieldClient		= "soto:client";
// Name of the active backend ("OpenVPN", ...).
static const char* const kFieldBackend		= "soto:backend";

// VPNStats fields:
static const char* const kFieldBytesIn			= "soto:bytesIn";
static const char* const kFieldBytesOut			= "soto:bytesOut";
static const char* const kFieldConnectedSince	= "soto:connectedSince";

// Tunnel addresses, populated once a session is up.
// kFieldLocalIP  = the IP the VPN server assigned to us inside the tunnel.
// kFieldRemoteIP = the IP/hostname of the VPN server itself (as seen on the
// underlying transport).
static const char* const kFieldLocalIP			= "soto:localIP";
static const char* const kFieldRemoteIP			= "soto:remoteIP";

// Transient connect-time credentials. Plaintext; never persisted by the
// daemon. The GUI strips them from the message after delivery.
static const char* const kFieldUsername			= "soto:auth:username";
static const char* const kFieldPassword			= "soto:auth:password";

// VPNProfile fields:
static const char* const kFieldProfileName		= "soto:profile:name";
static const char* const kFieldProfileServer	= "soto:profile:server";
static const char* const kFieldProfilePort		= "soto:profile:port";
static const char* const kFieldProfileBackend	= "soto:profile:backendType";
static const char* const kFieldProfileUsername	= "soto:profile:username";
static const char* const kFieldProfileConfigPath = "soto:profile:configPath";
// Transport protocol as a string ("udp" or "tcp"). Defaults to "udp".
static const char* const kFieldProfileProtocol	= "soto:profile:protocol";


#endif	// VPN_PROTOCOL_H
