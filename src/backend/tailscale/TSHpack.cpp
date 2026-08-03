/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSHpack.h"

#include <string.h>


namespace ts {

// HPACK static table (RFC 7541 Appendix A), indices 1..61. Empty value == "".
struct StaticEntry {
	const char*	name;
	const char*	value;
};

static const StaticEntry kStatic[] = {
	{ "", "" },									// index 0 unused
	{ ":authority", "" },						// 1
	{ ":method", "GET" },						// 2
	{ ":method", "POST" },						// 3
	{ ":path", "/" },							// 4
	{ ":path", "/index.html" },					// 5
	{ ":scheme", "http" },						// 6
	{ ":scheme", "https" },						// 7
	{ ":status", "200" },						// 8
	{ ":status", "204" },						// 9
	{ ":status", "206" },						// 10
	{ ":status", "304" },						// 11
	{ ":status", "400" },						// 12
	{ ":status", "404" },						// 13
	{ ":status", "500" },						// 14
	{ "accept-charset", "" },					// 15
	{ "accept-encoding", "gzip, deflate" },		// 16
	{ "accept-language", "" },					// 17
	{ "accept-ranges", "" },					// 18
	{ "accept", "" },							// 19
	{ "access-control-allow-origin", "" },		// 20
	{ "age", "" },								// 21
	{ "allow", "" },							// 22
	{ "authorization", "" },					// 23
	{ "cache-control", "" },					// 24
	{ "content-disposition", "" },				// 25
	{ "content-encoding", "" },					// 26
	{ "content-language", "" },					// 27
	{ "content-length", "" },					// 28
	{ "content-location", "" },					// 29
	{ "content-range", "" },					// 30
	{ "content-type", "" },						// 31
	{ "cookie", "" },							// 32
	{ "date", "" },								// 33
	{ "etag", "" },								// 34
	{ "expect", "" },							// 35
	{ "expires", "" },							// 36
	{ "from", "" },								// 37
	{ "host", "" },								// 38
	{ "if-match", "" },							// 39
	{ "if-modified-since", "" },				// 40
	{ "if-none-match", "" },					// 41
	{ "if-range", "" },							// 42
	{ "if-unmodified-since", "" },				// 43
	{ "last-modified", "" },					// 44
	{ "link", "" },								// 45
	{ "location", "" },							// 46
	{ "max-forwards", "" },						// 47
	{ "proxy-authenticate", "" },				// 48
	{ "proxy-authorization", "" },				// 49
	{ "range", "" },							// 50
	{ "referer", "" },							// 51
	{ "refresh", "" },							// 52
	{ "retry-after", "" },						// 53
	{ "server", "" },							// 54
	{ "set-cookie", "" },						// 55
	{ "strict-transport-security", "" },		// 56
	{ "transfer-encoding", "" },				// 57
	{ "user-agent", "" },						// 58
	{ "vary", "" },								// 59
	{ "via", "" },								// 60
	{ "www-authenticate", "" }					// 61
};
static const uint32 kStaticCount = 61;


// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

HpackDecoder::HpackDecoder()
	:
	fDynamicSize(0),
	fMaxDynamicSize(4096)
{
}


void
HpackDecoder::SetMaxDynamicSize(size_t maxSize)
{
	fMaxDynamicSize = maxSize;
	_Evict();
}


bool
HpackDecoder::_DecodeInteger(const uint8* buf, size_t len, size_t& pos,
	uint8 prefixBits, uint32& outValue)
{
	if (pos >= len)
		return false;
	uint32 mask = (1u << prefixBits) - 1;
	uint32 value = buf[pos++] & mask;
	if (value < mask) {
		outValue = value;
		return true;
	}
	// Continuation: 7 bits per byte, MSB = "more".
	uint32 shift = 0;
	while (pos < len) {
		uint8 b = buf[pos++];
		value += (uint32)(b & 0x7f) << shift;
		if ((b & 0x80) == 0) {
			outValue = value;
			return true;
		}
		shift += 7;
		if (shift > 28)			// guard against overflow / malformed input
			return false;
	}
	return false;	// ran out of bytes mid-integer
}


status_t
HpackDecoder::_DecodeString(const uint8* buf, size_t len, size_t& pos,
	BString& out)
{
	if (pos >= len)
		return B_BAD_DATA;
	bool huffman = (buf[pos] & 0x80) != 0;
	uint32 strLen = 0;
	if (!_DecodeInteger(buf, len, pos, 7, strLen))
		return B_BAD_DATA;
	if (pos + strLen > len)
		return B_BAD_DATA;

	if (huffman) {
		// Huffman string decoding lands in the next change; refuse rather than
		// return garbage so a caller knows to wait for it.
		pos += strLen;
		return B_NOT_SUPPORTED;
	}

	out.SetTo((const char*)(buf + pos), strLen);
	pos += strLen;
	return B_OK;
}


bool
HpackDecoder::_Lookup(uint32 index, HpackHeader& out) const
{
	if (index == 0)
		return false;
	if (index <= kStaticCount) {
		out.name = kStatic[index].name;
		out.value = kStatic[index].value;
		return true;
	}
	uint32 dynIndex = index - kStaticCount - 1;	// 0 == newest
	if (dynIndex >= fDynamic.size())
		return false;
	out = fDynamic[dynIndex];
	return true;
}


void
HpackDecoder::_AddDynamic(const HpackHeader& header)
{
	fDynamic.insert(fDynamic.begin(), header);
	fDynamicSize += header.name.Length() + header.value.Length() + 32;
	_Evict();
}


void
HpackDecoder::_Evict()
{
	while (fDynamicSize > fMaxDynamicSize && !fDynamic.empty()) {
		const HpackHeader& oldest = fDynamic.back();
		fDynamicSize -= oldest.name.Length() + oldest.value.Length() + 32;
		fDynamic.pop_back();
	}
}


status_t
HpackDecoder::Decode(const uint8* buf, size_t len, std::vector<HpackHeader>& out)
{
	size_t pos = 0;
	while (pos < len) {
		uint8 b = buf[pos];

		if ((b & 0x80) != 0) {
			// Indexed Header Field.
			uint32 index = 0;
			if (!_DecodeInteger(buf, len, pos, 7, index))
				return B_BAD_DATA;
			HpackHeader h;
			if (!_Lookup(index, h))
				return B_BAD_DATA;
			out.push_back(h);
		} else if ((b & 0x40) != 0) {
			// Literal Header Field with Incremental Indexing.
			uint32 nameIndex = 0;
			if (!_DecodeInteger(buf, len, pos, 6, nameIndex))
				return B_BAD_DATA;
			HpackHeader h;
			if (nameIndex != 0) {
				HpackHeader named;
				if (!_Lookup(nameIndex, named))
					return B_BAD_DATA;
				h.name = named.name;
			} else {
				status_t r = _DecodeString(buf, len, pos, h.name);
				if (r != B_OK)
					return r;
			}
			status_t r = _DecodeString(buf, len, pos, h.value);
			if (r != B_OK)
				return r;
			out.push_back(h);
			_AddDynamic(h);
		} else if ((b & 0x20) != 0) {
			// Dynamic Table Size Update.
			uint32 newSize = 0;
			if (!_DecodeInteger(buf, len, pos, 5, newSize))
				return B_BAD_DATA;
			SetMaxDynamicSize(newSize);
		} else {
			// Literal without Indexing (0x00) or Never Indexed (0x10).
			uint32 nameIndex = 0;
			if (!_DecodeInteger(buf, len, pos, 4, nameIndex))
				return B_BAD_DATA;
			HpackHeader h;
			if (nameIndex != 0) {
				HpackHeader named;
				if (!_Lookup(nameIndex, named))
					return B_BAD_DATA;
				h.name = named.name;
			} else {
				status_t r = _DecodeString(buf, len, pos, h.name);
				if (r != B_OK)
					return r;
			}
			status_t r = _DecodeString(buf, len, pos, h.value);
			if (r != B_OK)
				return r;
			out.push_back(h);
		}
	}
	return B_OK;
}


// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

void
HpackEncoder::_EncodeInteger(std::vector<uint8>& out, uint8 prefixBits,
	uint8 prefixMask, uint32 value)
{
	uint32 max = (1u << prefixBits) - 1;
	if (value < max) {
		out.push_back(prefixMask | (uint8)value);
		return;
	}
	out.push_back(prefixMask | (uint8)max);
	value -= max;
	while (value >= 128) {
		out.push_back((uint8)((value & 0x7f) | 0x80));
		value >>= 7;
	}
	out.push_back((uint8)value);
}


void
HpackEncoder::_EncodeRawString(std::vector<uint8>& out, const char* str,
	size_t len)
{
	// H flag = 0 (raw), 7-bit length prefix.
	_EncodeInteger(out, 7, 0x00, (uint32)len);
	for (size_t i = 0; i < len; i++)
		out.push_back((uint8)str[i]);
}


void
HpackEncoder::AddHeader(std::vector<uint8>& out, const char* name,
	const char* value)
{
	// Look for a full (name+value) or name-only match in the static table.
	int fullMatch = -1;
	int nameMatch = -1;
	for (uint32 i = 1; i <= kStaticCount; i++) {
		if (strcmp(kStatic[i].name, name) != 0)
			continue;
		if (nameMatch < 0)
			nameMatch = (int)i;
		if (strcmp(kStatic[i].value, value) == 0) {
			fullMatch = (int)i;
			break;
		}
	}

	if (fullMatch >= 0) {
		// Indexed Header Field: 1xxxxxxx.
		_EncodeInteger(out, 7, 0x80, (uint32)fullMatch);
		return;
	}

	// Literal without Indexing: 0000xxxx name index (or 0 + literal name),
	// then a raw literal value.
	if (nameMatch >= 0) {
		_EncodeInteger(out, 4, 0x00, (uint32)nameMatch);
	} else {
		out.push_back(0x00);	// name index 0 -> literal name follows
		_EncodeRawString(out, name, strlen(name));
	}
	_EncodeRawString(out, value, strlen(value));
}

}	// namespace ts
