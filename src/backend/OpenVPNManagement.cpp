/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "OpenVPNManagement.h"

#include <stdio.h>
#include <stdlib.h>


// --- small string helpers --------------------------------------------------

static std::vector<std::string>
split(const std::string& input, char delimiter)
{
	std::vector<std::string> fields;
	std::string current;
	for (size_t i = 0; i < input.length(); i++) {
		if (input[i] == delimiter) {
			fields.push_back(current);
			current.clear();
		} else {
			current += input[i];
		}
	}
	fields.push_back(current);
	return fields;
}


static std::string
trim(const std::string& input)
{
	size_t start = 0;
	size_t end = input.length();
	while (start < end && (input[start] == ' ' || input[start] == '\t'))
		start++;
	while (end > start && (input[end - 1] == ' ' || input[end - 1] == '\t'
			|| input[end - 1] == '\r' || input[end - 1] == '\n')) {
		end--;
	}
	return input.substr(start, end - start);
}


// Extract the text inside the first pair of single quotes, e.g.
// "Need 'Auth' username/password" -> "Auth". Returns "" if not found.
static std::string
extract_quoted(const std::string& input)
{
	size_t open = input.find('\'');
	if (open == std::string::npos)
		return "";
	size_t close = input.find('\'', open + 1);
	if (close == std::string::npos)
		return "";
	return input.substr(open + 1, close - open - 1);
}


static bool
starts_with(const std::string& input, const char* prefix)
{
	size_t length = 0;
	while (prefix[length] != '\0')
		length++;
	if (input.length() < length)
		return false;
	return input.compare(0, length, prefix) == 0;
}


// --- OpenVPNEvent ----------------------------------------------------------

OpenVPNEvent::OpenVPNEvent()
	:
	type(OPENVPN_EVENT_UNKNOWN),
	mappedState(VPN_STATE_ERROR),
	bytesIn(0),
	bytesOut(0)
{
}


// --- OpenVPNManagement -----------------------------------------------------

VPNState
OpenVPNManagement::StateForName(const std::string& name)
{
	// OpenVPN connection stages, mapped onto our coarser VPNState. See the
	// management notes for the full list of state strings.
	if (name == "CONNECTING" || name == "RESOLVE" || name == "TCP_CONNECT"
			|| name == "WAIT") {
		return VPN_STATE_CONNECTING;
	}
	if (name == "AUTH" || name == "AUTH_PENDING" || name == "GET_CONFIG"
			|| name == "ASSIGN_IP" || name == "ADD_ROUTES") {
		// AUTH_PENDING is openvpn 2.6's deferred/2FA-auth state: still
		// progressing, not an error. Without it here it fell through to the
		// unknown -> ERROR default and flipped the UI to "error" mid-handshake
		// on servers that use web/2FA auth.
		return VPN_STATE_AUTHENTICATING;
	}
	if (name == "CONNECTED")
		return VPN_STATE_CONNECTED;
	if (name == "RECONNECTING")
		return VPN_STATE_RECONNECTING;
	if (name == "EXITING")
		return VPN_STATE_DISCONNECTED;

	return VPN_STATE_ERROR;
}


OpenVPNEvent
OpenVPNManagement::ParseLine(const std::string& rawLine)
{
	OpenVPNEvent event;
	std::string line = trim(rawLine);
	event.raw = line;

	if (line.empty())
		return event;

	// Real-time notifications are ">TYPE:payload".
	if (line[0] == '>') {
		size_t colon = line.find(':');
		std::string tag = (colon == std::string::npos)
			? line.substr(1) : line.substr(1, colon - 1);
		std::string payload = (colon == std::string::npos)
			? "" : line.substr(colon + 1);

		if (tag == "STATE") {
			event.type = OPENVPN_EVENT_STATE;
			// time,state,description,local-ip,remote-ip,remote-port,...
			std::vector<std::string> f = split(payload, ',');
			if (f.size() > 1)
				event.stateName = f[1];
			if (f.size() > 2)
				event.stateDetail = f[2];
			if (f.size() > 3)
				event.localIP = f[3];
			if (f.size() > 4)
				event.remoteIP = f[4];
			event.mappedState = StateForName(event.stateName);
			return event;
		}

		if (tag == "BYTECOUNT") {
			event.type = OPENVPN_EVENT_BYTECOUNT;
			std::vector<std::string> f = split(payload, ',');
			if (f.size() > 0)
				event.bytesIn = strtoull(f[0].c_str(), NULL, 10);
			if (f.size() > 1)
				event.bytesOut = strtoull(f[1].c_str(), NULL, 10);
			return event;
		}

		if (tag == "PASSWORD") {
			if (starts_with(payload, "Verification Failed")) {
				event.type = OPENVPN_EVENT_AUTH_FAILED;
			} else {
				event.type = OPENVPN_EVENT_PASSWORD_REQUEST;
			}
			event.realm = extract_quoted(payload);
			event.message = payload;
			return event;
		}

		if (tag == "HOLD") {
			event.type = OPENVPN_EVENT_HOLD;
			event.message = payload;
			return event;
		}

		if (tag == "LOG") {
			event.type = OPENVPN_EVENT_LOG;
			// payload format is "time,flags,message". The message itself
			// regularly contains commas (PUSH_REPLY, ifconfig command, ...),
			// so don't split it -- just skip past the first two fields.
			size_t firstComma = payload.find(',');
			size_t secondComma = (firstComma != std::string::npos)
				? payload.find(',', firstComma + 1) : std::string::npos;
			event.message = (secondComma != std::string::npos)
				? payload.substr(secondComma + 1) : payload;
			return event;
		}

		if (tag == "INFO") {
			event.type = OPENVPN_EVENT_INFO;
			event.message = payload;
			return event;
		}

		if (tag == "FATAL") {
			event.type = OPENVPN_EVENT_FATAL;
			event.message = payload;
			return event;
		}

		event.type = OPENVPN_EVENT_UNKNOWN;
		return event;
	}

	// Plain command replies.
	if (starts_with(line, "SUCCESS:")) {
		event.type = OPENVPN_EVENT_SUCCESS;
		event.message = trim(line.substr(8));
		return event;
	}
	if (starts_with(line, "ERROR:")) {
		event.type = OPENVPN_EVENT_ERROR;
		event.message = trim(line.substr(6));
		return event;
	}

	event.type = OPENVPN_EVENT_UNKNOWN;
	return event;
}


std::vector<OpenVPNEvent>
OpenVPNManagement::Feed(const std::string& chunk)
{
	std::vector<OpenVPNEvent> events;
	fBuffer += chunk;

	size_t newline;
	while ((newline = fBuffer.find('\n')) != std::string::npos) {
		std::string line = fBuffer.substr(0, newline);
		fBuffer.erase(0, newline + 1);
		// ParseLine trims any trailing '\r'.
		events.push_back(ParseLine(line));
	}

	return events;
}


std::string
OpenVPNManagement::CommandStateOn()
{
	return "state on";
}


std::string
OpenVPNManagement::CommandByteCount(int intervalSeconds)
{
	char buffer[32];
	snprintf(buffer, sizeof(buffer), "bytecount %d", intervalSeconds);
	return std::string(buffer);
}


std::string
OpenVPNManagement::CommandHoldRelease()
{
	return "hold release";
}


std::string
OpenVPNManagement::CommandUsername(const std::string& realm,
	const std::string& username)
{
	return "username \"" + _Escape(realm) + "\" \"" + _Escape(username) + "\"";
}


std::string
OpenVPNManagement::CommandPassword(const std::string& realm,
	const std::string& password)
{
	return "password \"" + _Escape(realm) + "\" \"" + _Escape(password) + "\"";
}


std::string
OpenVPNManagement::CommandSignalTerm()
{
	return "signal SIGTERM";
}


// The management interface treats backslash and double-quote specially inside
// quoted arguments; escape them so passwords with those characters survive.
std::string
OpenVPNManagement::_Escape(const std::string& value)
{
	std::string escaped;
	for (size_t i = 0; i < value.length(); i++) {
		if (value[i] == '\\' || value[i] == '"')
			escaped += '\\';
		escaped += value[i];
	}
	return escaped;
}
