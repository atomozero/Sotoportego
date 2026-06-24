/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "VPNProfile.h"

#include <Message.h>

#include "VPNProtocol.h"


VPNProfile::VPNProfile()
	:
	fBackendType(VPN_BACKEND_OPENVPN),
	fName(""),
	fServer(""),
	fPort(1194),
	fUsername(""),
	fConfigPath("")
{
}


VPNProfile::~VPNProfile()
{
}


status_t
VPNProfile::Archive(BMessage* into) const
{
	if (into == NULL)
		return B_BAD_VALUE;

	status_t result = into->AddInt32(kFieldProfileBackend, (int32)fBackendType);
	if (result == B_OK)
		result = into->AddString(kFieldProfileName, fName);
	if (result == B_OK)
		result = into->AddString(kFieldProfileServer, fServer);
	if (result == B_OK)
		result = into->AddInt32(kFieldProfilePort, (int32)fPort);
	if (result == B_OK)
		result = into->AddString(kFieldProfileUsername, fUsername);
	if (result == B_OK)
		result = into->AddString(kFieldProfileConfigPath, fConfigPath);

	return result;
}


status_t
VPNProfile::Unarchive(const BMessage& from)
{
	int32 intValue;
	if (from.FindInt32(kFieldProfileBackend, &intValue) == B_OK)
		fBackendType = (VPNBackendType)intValue;

	BString stringValue;
	if (from.FindString(kFieldProfileName, &stringValue) == B_OK)
		fName = stringValue;
	if (from.FindString(kFieldProfileServer, &stringValue) == B_OK)
		fServer = stringValue;
	if (from.FindInt32(kFieldProfilePort, &intValue) == B_OK)
		fPort = (uint16)intValue;
	if (from.FindString(kFieldProfileUsername, &stringValue) == B_OK)
		fUsername = stringValue;
	if (from.FindString(kFieldProfileConfigPath, &stringValue) == B_OK)
		fConfigPath = stringValue;

	return B_OK;
}
