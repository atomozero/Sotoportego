/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSConfig.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <Directory.h>
#include <File.h>
#include <FindDirectory.h>
#include <Message.h>
#include <Path.h>


namespace ts {

const char* const kDefaultControlURL = "https://controlplane.tailscale.com";

// Sub-directory of the app settings dir that holds every tailnet identity.
static const char* const kSettingsDir	= "Sotoportego";
static const char* const kTailscaleDir	= "tailscale";
static const char* const kConfigLeaf	= "config";

// BMessage field the flattened config is stored under.
static const char* const kFieldControlURL = "control_url";


TSConfig::TSConfig()
{
	MakeDefault();
}


void
TSConfig::MakeDefault()
{
	fControlURL = kDefaultControlURL;
	fAuthKey = "";
	fProfileName = "";
}


void
TSConfig::SetControlURL(const char* url)
{
	if (url == NULL || *url == '\0') {
		fControlURL = kDefaultControlURL;
		return;
	}
	fControlURL = url;
	// Normalise away a single trailing slash so callers can always append
	// "/ts2021" etc. without doubling the separator.
	if (fControlURL.Length() > 0
			&& fControlURL[fControlURL.Length() - 1] == '/') {
		fControlURL.Truncate(fControlURL.Length() - 1);
	}
}


status_t
TSConfig::Load(const char* profileName)
{
	if (profileName == NULL || *profileName == '\0')
		return B_BAD_VALUE;

	// A fresh identity (no config file yet) is the common first-run case, so
	// start from defaults and only overlay whatever the file provides.
	MakeDefault();
	fProfileName = profileName;

	BPath path;
	status_t result = _ConfigFilePath(profileName, &path, false);
	if (result != B_OK)
		return result;

	BFile file(path.Path(), B_READ_ONLY);
	if (file.InitCheck() == B_ENTRY_NOT_FOUND)
		return B_OK;	// no persisted config yet -> defaults stand
	if (file.InitCheck() != B_OK)
		return file.InitCheck();

	BMessage stored;
	result = stored.Unflatten(&file);
	if (result != B_OK)
		return result;

	const char* url = NULL;
	if (stored.FindString(kFieldControlURL, &url) == B_OK)
		SetControlURL(url);

	return B_OK;
}


status_t
TSConfig::Save() const
{
	if (fProfileName.Length() == 0)
		return B_BAD_VALUE;

	BPath path;
	status_t result = _ConfigFilePath(fProfileName.String(), &path, true);
	if (result != B_OK)
		return result;

	BMessage stored;
	result = stored.AddString(kFieldControlURL, fControlURL);
	if (result != B_OK)
		return result;

	// Atomic replace, mirroring ProfileStore: flatten into a sibling temp file
	// and rename() over the real path so an interrupted write can't leave a
	// truncated config behind.
	BString tempPath(path.Path());
	tempPath << ".tmp";

	BFile file(tempPath.String(),
		B_WRITE_ONLY | B_CREATE_FILE | B_ERASE_FILE);
	if (file.InitCheck() != B_OK)
		return file.InitCheck();

	result = stored.Flatten(&file);
	if (result != B_OK) {
		unlink(tempPath.String());
		return result;
	}

	// Close before rename so the bytes are flushed first.
	file.Unset();

	if (rename(tempPath.String(), path.Path()) != 0) {
		status_t renameErr = B_FROM_POSIX_ERROR(errno);
		unlink(tempPath.String());
		return renameErr;
	}
	return B_OK;
}


status_t
TSConfig::BaseDir(BPath* out, bool createDir)
{
	if (out == NULL)
		return B_BAD_VALUE;

	status_t result = find_directory(B_USER_SETTINGS_DIRECTORY, out);
	if (result != B_OK)
		return result;

	result = out->Append(kSettingsDir);
	if (result != B_OK)
		return result;
	result = out->Append(kTailscaleDir);
	if (result != B_OK)
		return result;

	if (createDir) {
		// mkdir -p semantics: creates intermediate parents, ignores EEXIST.
		result = create_directory(out->Path(), 0700);
		if (result != B_OK)
			return result;
	}

	return B_OK;
}


status_t
TSConfig::IdentityDir(const char* profileName, BPath* out, bool createDir)
{
	if (out == NULL || profileName == NULL || *profileName == '\0')
		return B_BAD_VALUE;

	status_t result = BaseDir(out, createDir);
	if (result != B_OK)
		return result;

	BString component = _SanitizeComponent(profileName);
	result = out->Append(component.String());
	if (result != B_OK)
		return result;

	if (createDir) {
		result = create_directory(out->Path(), 0700);
		if (result != B_OK)
			return result;
	}

	return B_OK;
}


// Reduce an arbitrary profile name to a single filesystem-safe path component:
// keep [A-Za-z0-9._-], fold everything else (spaces, slashes, unicode bytes) to
// '_'. Leading dots are stripped so the result can never be "." / ".." or a
// hidden entry, guaranteeing it stays a child of the base directory.
BString
TSConfig::_SanitizeComponent(const char* name)
{
	BString out;
	for (const char* p = name; *p != '\0'; p++) {
		unsigned char c = (unsigned char)*p;
		if (isalnum(c) || c == '.' || c == '_' || c == '-')
			out << (char)c;
		else
			out << '_';
	}

	while (out.Length() > 0 && out[0] == '.')
		out.Remove(0, 1);

	if (out.Length() == 0)
		out = "_";

	return out;
}


status_t
TSConfig::_ConfigFilePath(const char* profileName, BPath* out, bool createDir)
{
	status_t result = IdentityDir(profileName, out, createDir);
	if (result != B_OK)
		return result;
	return out->Append(kConfigLeaf);
}

}	// namespace ts
