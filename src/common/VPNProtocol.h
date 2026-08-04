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
	kMsgListProfiles	= 'sLst',

	// C -> S : ask the daemon for the current VPNGate public-server
	// catalogue. The daemon caches the catalogue; if a cached copy is fresh
	// enough it replies immediately, otherwise it kicks off the fetcher
	// thread and answers once the response arrives.
	kMsgRequestVPNGate	= 'sRVG',

	// S -> C : reply to kMsgRequestVPNGate (and broadcast to all subscribers
	// when a fresh fetch completes). Carries one nested BMessage per server
	// under kFieldVPNGateServer, or kFieldError if the fetch failed.
	kMsgVPNGateList		= 'sLVG',

	// C -> S : connect to a VPNGate server picked from the map. The .ovpn
	// body is shipped in-message (base64 under kFieldVPNGateConfigBase64)
	// so the daemon doesn't have to keep the whole catalogue resident.
	kMsgConnectVPNGate	= 'sCVG'
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

// Apparent egress country, as resolved by the daemon's geo-lookup that
// runs *through* the tunnel after CONNECTED. Optional; absent before the
// lookup completes and on any state other than CONNECTED.
static const char* const kFieldCountry			= "soto:country";

// Apparent egress (public) IP, also resolved by the geo-lookup. Same
// lifetime as kFieldCountry; this is what the outside world sees us as,
// which is NOT the same as kFieldLocalIP (the private in-tunnel address).
static const char* const kFieldExternalIP		= "soto:externalIP";

// "Home" location -- where the daemon's geo-lookup placed us when no VPN
// was up. Resolved once at daemon startup (and refreshed after every
// disconnect), broadcast in every status update so the map can draw the
// "you are here" pin without needing its own HTTP client.
// kFieldHomeIP / kFieldHomeCountry are strings; kFieldHomeLat/Lon are
// floats. Any of them may be absent on lookup failure.
static const char* const kFieldHomeIP			= "soto:home:ip";
static const char* const kFieldHomeCountry		= "soto:home:country";
static const char* const kFieldHomeLat			= "soto:home:lat";
static const char* const kFieldHomeLon			= "soto:home:lon";

// The vpngate host the active session was started against (if any).
// Empty / absent outside the [Connecting .. Connected] window; the map
// uses it to know which pin should anchor the "connection arc".
static const char* const kFieldConnectedHost	= "soto:connected:host";

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
// Optional Tailscale pre-auth key: when set, the node registers non-
// interactively instead of opening a browser for SSO login.
static const char* const kFieldProfileAuthKey	= "soto:profile:authKey";

// VPNGate catalogue fields. A kMsgVPNGateList message carries one nested
// BMessage per server under kFieldVPNGateServer; each nested message in
// turn carries the per-server fields below.
static const char* const kFieldVPNGateServer			= "soto:vg:server";
static const char* const kFieldVPNGateHost				= "soto:vg:host";
static const char* const kFieldVPNGateIP				= "soto:vg:ip";
static const char* const kFieldVPNGateCountryShort		= "soto:vg:cc";
static const char* const kFieldVPNGateCountryLong		= "soto:vg:country";
static const char* const kFieldVPNGateScore				= "soto:vg:score";
static const char* const kFieldVPNGatePing				= "soto:vg:ping";
static const char* const kFieldVPNGateSpeedMbps			= "soto:vg:speed";
static const char* const kFieldVPNGateSessions			= "soto:vg:sessions";
static const char* const kFieldVPNGateLogPolicy			= "soto:vg:logtype";
static const char* const kFieldVPNGateLatitude			= "soto:vg:lat";
static const char* const kFieldVPNGateLongitude			= "soto:vg:lon";
// Base64-encoded raw OpenVPN config file body for the server. Decoded by
// the daemon when kMsgConnectVPNGate arrives.
static const char* const kFieldVPNGateConfigBase64		= "soto:vg:ovpn";

// Generic error string on a failed request (e.g. fetcher couldn't reach
// the catalogue server, parse failed, ...). Optional; absent means success.
static const char* const kFieldError					= "soto:error";


#endif	// VPN_PROTOCOL_H
