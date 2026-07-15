/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "ProfileStore.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <Directory.h>
#include <File.h>
#include <FindDirectory.h>
#include <Message.h>
#include <Path.h>

#include "VPNProtocol.h"


static const char* const kSettingsDir = "Sotoportego";
static const char* const kSettingsFile = "profiles";


ProfileStore::ProfileStore()
{
}


ProfileStore::~ProfileStore()
{
}


status_t
ProfileStore::Load()
{
	BPath path;
	status_t result = _SettingsPath(&path, false);
	if (result != B_OK)
		return result;

	BFile file(path.Path(), B_READ_ONLY);
	if (file.InitCheck() == B_ENTRY_NOT_FOUND)
		return B_OK;	// fresh install, nothing to load
	if (file.InitCheck() != B_OK)
		return file.InitCheck();

	BMessage stored;
	result = stored.Unflatten(&file);
	if (result != B_OK)
		return result;

	fProfiles.clear();
	BMessage archive;
	for (int32 i = 0; stored.FindMessage(kFieldProfile, i, &archive) == B_OK;
			i++) {
		VPNProfile profile;
		profile.Unarchive(archive);
		// Names must be unique; skip any malformed leftover with an empty
		// name rather than letting it confuse the by-name lookups.
		if (profile.fName.Length() == 0)
			continue;
		fProfiles.push_back(profile);
	}

	printf("[server] loaded %zu profile(s) from %s\n",
		fProfiles.size(), path.Path());
	return B_OK;
}


status_t
ProfileStore::Save(const VPNProfile& profile)
{
	if (profile.fName.Length() == 0)
		return B_BAD_VALUE;

	for (size_t i = 0; i < fProfiles.size(); i++) {
		if (fProfiles[i].fName == profile.fName) {
			fProfiles[i] = profile;
			return _WriteToDisk();
		}
	}

	fProfiles.push_back(profile);
	return _WriteToDisk();
}


status_t
ProfileStore::Delete(const char* name)
{
	if (name == NULL)
		return B_BAD_VALUE;

	for (size_t i = 0; i < fProfiles.size(); i++) {
		if (fProfiles[i].fName == name) {
			fProfiles.erase(fProfiles.begin() + i);
			return _WriteToDisk();
		}
	}

	return B_OK;	// idempotent: deleting an absent profile is fine
}


status_t
ProfileStore::ArchiveAll(BMessage* into) const
{
	if (into == NULL)
		return B_BAD_VALUE;

	for (size_t i = 0; i < fProfiles.size(); i++) {
		BMessage archive;
		status_t result = fProfiles[i].Archive(&archive);
		if (result != B_OK)
			return result;
		result = into->AddMessage(kFieldProfile, &archive);
		if (result != B_OK)
			return result;
	}
	return B_OK;
}


status_t
ProfileStore::_WriteToDisk() const
{
	BPath path;
	status_t result = _SettingsPath(&path, true);
	if (result != B_OK)
		return result;

	BMessage stored;
	for (size_t i = 0; i < fProfiles.size(); i++) {
		BMessage archive;
		result = fProfiles[i].Archive(&archive);
		if (result != B_OK)
			return result;
		result = stored.AddMessage(kFieldProfile, &archive);
		if (result != B_OK)
			return result;
	}

	// Atomic replace: flatten into a sibling temp file and rename() over
	// the real path. A crash, power cut, or out-of-space halfway through
	// Flatten leaves the previous, valid `profiles` file in place. The
	// previous code did B_ERASE_FILE then Flatten, which truncated the
	// real file first -- if anything went wrong before Flatten finished,
	// the daemon woke up next time to an empty profile list.
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

	// Close BEFORE rename so the data is flushed to disk; BFile flushes
	// on destruction but we want the rename ordered after the flush.
	file.Unset();

	if (rename(tempPath.String(), path.Path()) != 0) {
		// rename() sets a positive POSIX errno; convert to Haiku's negative
		// status_t so callers' `!= B_OK` checks and strerror() see a real
		// error code rather than a small positive number that reads as
		// almost-success.
		status_t renameErr = B_FROM_POSIX_ERROR(errno);
		unlink(tempPath.String());
		return renameErr;
	}
	return B_OK;
}


status_t
ProfileStore::_SettingsPath(BPath* path, bool createDir) const
{
	if (path == NULL)
		return B_BAD_VALUE;

	status_t result = find_directory(B_USER_SETTINGS_DIRECTORY, path);
	if (result != B_OK)
		return result;

	result = path->Append(kSettingsDir);
	if (result != B_OK)
		return result;

	if (createDir) {
		// create_directory creates intermediate parents and ignores
		// "already exists"; equivalent to mkdir -p.
		result = create_directory(path->Path(), 0755);
		if (result != B_OK)
			return result;
	}

	return path->Append(kSettingsFile);
}
