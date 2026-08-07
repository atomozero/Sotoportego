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


// HPACK Huffman code table (RFC 7541 Appendix B), one (code, bitlength) per
// byte value 0..255. The 256th "EOS" symbol is intentionally absent: an EOS in
// the middle of a string is a decode error, and trailing EOS bits are just
// padding handled below.
static const uint32 kHuffCode[256] = {
	0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6,
	0xfffffe7, 0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea,
	0x3ffffffd, 0xfffffeb, 0xfffffec, 0xfffffed, 0xfffffee, 0xfffffef,
	0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4,
	0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa,
	0xffffffb, 0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa,
	0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18, 0x0, 0x1, 0x2, 0x19, 0x1a,
	0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
	0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
	0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
	0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22, 0x7ffd, 0x3,
	0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75, 0x28, 0x29,
	0x2a, 0x7, 0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a,
	0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc, 0xfffe6, 0x3fffd2,
	0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9, 0x3fffd6,
	0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
	0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2,
	0x7fffe3, 0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6,
	0x7fffe7, 0xffffef, 0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc,
	0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0,
	0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec, 0x1fffe0, 0x1fffe1, 0x3fffe0,
	0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2,
	0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1, 0x3ffffe0,
	0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
	0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5,
	0xfffff1, 0x1ffffed, 0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1,
	0x3ffffe7, 0x7ffffe2, 0xfffff2, 0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9,
	0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5, 0xfffec, 0xfffff3, 0xfffed,
	0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3, 0x3fffea, 0x3fffeb,
	0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4, 0x3ffffeb,
	0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9,
	0x7ffffea, 0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee,
	0x7ffffef, 0x7fffff0, 0x3ffffee
};

static const uint8 kHuffLen[256] = {
	13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28,
	28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12,
	13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7,
	8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6,
	5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
	20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24,
	22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20, 22,
	22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22,
	23, 23, 20, 22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25,
	26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24, 21, 21,
	26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25,
	24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27,
	27, 26
};


// Decode an HPACK Huffman string. Reads bits MSB-first; because the codes are
// prefix-free, the first (accumulated-bits, length) pair that matches a symbol
// is unambiguously that symbol. Trailing bits (< 8, all ones) are EOS padding.
static status_t
huffman_decode(const uint8* in, size_t len, BString& out)
{
	out = "";
	uint32 acc = 0;
	int accLen = 0;

	for (size_t i = 0; i < len; i++) {
		for (int bit = 7; bit >= 0; bit--) {
			acc = (acc << 1) | (uint32)((in[i] >> bit) & 1);
			accLen++;
			if (accLen > 30)
				return B_BAD_DATA;	// no code is longer than 30 bits

			int sym = -1;
			for (int s = 0; s < 256; s++) {
				if (kHuffLen[s] == accLen && kHuffCode[s] == acc) {
					sym = s;
					break;
				}
			}
			if (sym >= 0) {
				out << (char)sym;
				acc = 0;
				accLen = 0;
			}
		}
	}

	// Any leftover bits must be a proper (< 8-bit) all-ones EOS padding.
	if (accLen >= 8)
		return B_BAD_DATA;
	if (accLen > 0) {
		uint32 padMask = (1u << accLen) - 1;
		if ((acc & padMask) != padMask)
			return B_BAD_DATA;
	}
	return B_OK;
}


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
		status_t r = huffman_decode(buf + pos, strLen, out);
		pos += strLen;
		return r;
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
