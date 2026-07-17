/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "OpenVPNConfigParser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vector>


// --- tiny string helpers ---------------------------------------------------

// Parse a port token. Returns 0 when it isn't a whole number in 1..65535, so
// garbage ("abc") or an out-of-range value ("99999", which a bare (uint16)atoi
// would silently wrap to 33999) is rejected rather than becoming a plausible
// wrong port.
static uint16
parse_port(const std::string& token)
{
	char* end = NULL;
	long value = strtol(token.c_str(), &end, 10);
	if (end == token.c_str() || *end != '\0' || value < 1 || value > 65535)
		return 0;
	return (uint16)value;
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


// Split `input` into whitespace-separated tokens, stopping at the first
// '#' or ';' (OpenVPN's comment markers, when they appear outside of an
// inline block).
static void
tokenize(const std::string& input, std::vector<std::string>& tokens)
{
	std::string current;
	for (size_t i = 0; i < input.length(); i++) {
		char c = input[i];
		if (c == '#' || c == ';')
			break;
		if (c == ' ' || c == '\t') {
			if (!current.empty()) {
				tokens.push_back(current);
				current.clear();
			}
		} else {
			current += c;
		}
	}
	if (!current.empty())
		tokens.push_back(current);
}


// Map the various OpenVPN proto spellings onto our coarse "udp"/"tcp"
// distinction. "tcp" / "tcp-client" / "tcp4" / "tcp6" all become "tcp"; the
// rest fall back to "udp" (OpenVPN's default).
static std::string
normalize_proto(const std::string& raw)
{
	if (raw.length() >= 3 && raw.compare(0, 3, "tcp") == 0)
		return "tcp";
	return "udp";
}


// Derive a friendly profile name from a file path: take the basename and
// strip the trailing ".ovpn"/".conf" if present.
static std::string
default_name_for(const char* path)
{
	if (path == NULL || *path == '\0')
		return "";

	const char* slash = strrchr(path, '/');
	const char* base = (slash != NULL) ? slash + 1 : path;
	std::string name(base);

	const char* exts[] = { ".ovpn", ".conf", NULL };
	for (int i = 0; exts[i] != NULL; i++) {
		size_t extLen = strlen(exts[i]);
		if (name.length() > extLen
				&& name.compare(name.length() - extLen, extLen, exts[i]) == 0) {
			name.erase(name.length() - extLen);
			break;
		}
	}

	return name;
}


// --- OpenVPNConfigParser ---------------------------------------------------

void
OpenVPNConfigParser::ParseText(const std::string& text, VPNProfile& profile)
{
	// Set defensible defaults. The caller may have already populated fields
	// they want to preserve; only directives we recognise overwrite them.
	if (profile.fProtocol.IsEmpty())
		profile.fProtocol = "udp";
	if (profile.fPort == 0)
		profile.fPort = 1194;

	bool sawPort = false;
	// Configs with fail-over (ProtonVPN and others) carry several `remote`
	// lines; openvpn uses them all, but for the profile's display fields we
	// keep the FIRST one rather than letting the last overwrite it.
	bool sawRemote = false;
	// Name of the OpenVPN inline block we're currently inside (e.g. "ca" for
	// a <ca>...</ca> section), or empty when not in one. Empty until we hit an
	// opening tag.
	std::string inlineTag;

	// Split into lines on '\n'; trailing '\r' is handled by trim().
	size_t start = 0;
	while (start <= text.length()) {
		size_t end = text.find('\n', start);
		if (end == std::string::npos)
			end = text.length();

		std::string line = trim(text.substr(start, end - start));
		start = end + 1;

		if (line.empty() || line[0] == '#' || line[0] == ';')
			continue;

		// OpenVPN inline blocks -- <ca>, <cert>, <key>, <tls-auth>, etc. --
		// wrap PEM/base64 bodies that must never be interpreted as directives
		// (a body line could otherwise coincide with one). Swallow everything
		// from the opening tag through its matching close tag.
		if (!inlineTag.empty()) {
			if (line == "</" + inlineTag + ">")
				inlineTag.clear();
			continue;
		}
		if (line.size() >= 3 && line[0] == '<' && line[1] != '/'
				&& line[line.size() - 1] == '>') {
			inlineTag = line.substr(1, line.size() - 2);
			continue;
		}

		std::vector<std::string> tokens;
		tokenize(line, tokens);
		if (tokens.empty())
			continue;

		const std::string& directive = tokens[0];

		if (directive == "remote" && tokens.size() >= 2) {
			// Only the first remote drives the display fields; later fail-over
			// remotes are left to openvpn.
			if (!sawRemote) {
				profile.fServer = tokens[1].c_str();
				if (tokens.size() >= 3 && !sawPort) {
					uint16 p = parse_port(tokens[2]);
					if (p != 0)
						profile.fPort = p;
				}
				// The `sawPort` guard only governs the port: an explicit
				// `port` directive must win over the port carried on
				// `remote`. The transport protocol is independent, so the
				// remote's inline proto (4th token) is always honoured, even
				// when a `port` line appeared earlier.
				if (tokens.size() >= 4)
					profile.fProtocol = normalize_proto(tokens[3]).c_str();
				sawRemote = true;
			}
		} else if (directive == "proto" && tokens.size() >= 2) {
			profile.fProtocol = normalize_proto(tokens[1]).c_str();
		} else if (directive == "port" && tokens.size() >= 2) {
			// Only a valid port takes effect (and blocks a later remote
			// port); a bogus `port` line is ignored so it can't wipe out an
			// otherwise-usable port from `remote`.
			uint16 p = parse_port(tokens[1]);
			if (p != 0) {
				profile.fPort = p;
				sawPort = true;
			}
		} else if (directive == "auth-user-pass") {
			// The directive may take an optional filename argument; either
			// way it tells us interactive (or scripted) credentials are
			// required, so we mark the profile as having a username (empty
			// string == "ask the user").
			if (profile.fUsername.IsEmpty())
				profile.fUsername = "";
		}
	}
}


bool
OpenVPNConfigParser::ParseFile(const char* path, VPNProfile& profile)
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

	ParseText(text, profile);
	profile.fConfigPath = path;
	if (profile.fName.IsEmpty())
		profile.fName = default_name_for(path).c_str();

	return true;
}
