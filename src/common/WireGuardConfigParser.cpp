/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "WireGuardConfigParser.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// --- tiny string helpers ---------------------------------------------------

static std::string
trim(const std::string& input)
{
	size_t start = 0;
	size_t end = input.length();
	while (start < end && isspace((unsigned char)input[start]))
		start++;
	while (end > start && isspace((unsigned char)input[end - 1]))
		end--;
	return input.substr(start, end - start);
}


static std::string
to_lower(const std::string& input)
{
	std::string out = input;
	for (size_t i = 0; i < out.length(); i++)
		out[i] = (char)tolower((unsigned char)out[i]);
	return out;
}


// Split "host:port" into its parts, honouring the "[v6::addr]:port" bracket
// form. Leaves host/port untouched when the shape is unexpected.
static void
split_endpoint(const std::string& value, BString& host, uint16& port)
{
	std::string v = trim(value);
	if (v.empty())
		return;

	if (v[0] == '[') {
		size_t close = v.find(']');
		if (close == std::string::npos)
			return;
		host = v.substr(1, close - 1).c_str();
		size_t colon = v.find(':', close);
		if (colon != std::string::npos)
			port = (uint16)atoi(v.c_str() + colon + 1);
		return;
	}

	size_t colon = v.rfind(':');
	if (colon == std::string::npos) {
		host = v.c_str();
		return;
	}
	host = v.substr(0, colon).c_str();
	port = (uint16)atoi(v.c_str() + colon + 1);
}


// --- WireGuardConfigParser -------------------------------------------------

void
WireGuardConfigParser::ParseText(const std::string& text, WireGuardConfig& config)
{
	// Which INI section we're in. WireGuard uses [Interface] once and [Peer]
	// one-or-more times; we keep only the first peer (see the header).
	enum { kNone, kInterface, kPeer } section = kNone;
	// Which [Peer] block we're in (1-based). We only model the first peer;
	// later blocks change the section but no longer fill the struct.
	int peerCount = 0;

	size_t start = 0;
	while (start <= text.length()) {
		size_t end = text.find('\n', start);
		if (end == std::string::npos)
			end = text.length();

		std::string line = trim(text.substr(start, end - start));
		start = end + 1;

		if (line.empty() || line[0] == '#' || line[0] == ';')
			continue;

		// Section header?
		if (line[0] == '[') {
			size_t close = line.find(']');
			size_t inner = (close == std::string::npos ? line.length() : close) - 1;
			std::string name = to_lower(trim(line.substr(1, inner)));
			if (name == "interface")
				section = kInterface;
			else if (name == "peer") {
				section = kPeer;
				peerCount++;
			} else
				section = kNone;
			continue;
		}

		// key = value
		size_t eq = line.find('=');
		if (eq == std::string::npos)
			continue;
		std::string key = to_lower(trim(line.substr(0, eq)));
		std::string value = trim(line.substr(eq + 1));
		if (key.empty())
			continue;

		if (section == kInterface) {
			if (key == "privatekey")
				config.privateKey = value.c_str();
			else if (key == "address")
				config.address = value.c_str();
			else if (key == "dns")
				config.dns = value.c_str();
			else if (key == "listenport")
				config.listenPort = (uint16)atoi(value.c_str());
			else if (key == "mtu")
				config.mtu = (int32)atoi(value.c_str());
		} else if (section == kPeer && peerCount == 1) {
			// First [Peer] only.
			if (key == "publickey")
				config.peer.publicKey = value.c_str();
			else if (key == "presharedkey")
				config.peer.presharedKey = value.c_str();
			else if (key == "endpoint")
				split_endpoint(value, config.peer.endpointHost,
					config.peer.endpointPort);
			else if (key == "allowedips")
				config.peer.allowedIPs = value.c_str();
			else if (key == "persistentkeepalive")
				config.peer.persistentKeepalive = (int32)atoi(value.c_str());
		}
	}
}


bool
WireGuardConfigParser::ParseFile(const char* path, WireGuardConfig& config)
{
	if (path == NULL || *path == '\0')
		return false;

	FILE* file = fopen(path, "rb");
	if (file == NULL)
		return false;

	std::string text;
	char buffer[4096];
	for (;;) {
		size_t got = fread(buffer, 1, sizeof(buffer), file);
		if (got == 0)
			break;
		text.append(buffer, got);
	}
	fclose(file);

	ParseText(text, config);
	return true;
}
