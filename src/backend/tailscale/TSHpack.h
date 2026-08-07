/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_HPACK_H
#define TS_HPACK_H


#include <stddef.h>

#include <String.h>
#include <SupportDefs.h>

#include <vector>


// HPACK (RFC 7541) header compression for the HTTP/2 control channel.
//
// The encoder is deliberately minimal -- it never uses the dynamic table or
// Huffman coding when *emitting* (both are optional for a sender), which keeps
// request encoding simple and still fully valid: header names that exist in the
// static table are sent as indexed names, values as raw literals. The decoder
// must be complete, because the server (Go net/http2) freely uses the static
// and dynamic tables; Huffman-coded string decoding is added in the following
// change (this revision decodes raw literals and maintains the dynamic table,
// validated against the RFC 7541 C.3 non-Huffman request examples).
namespace ts {

struct HpackHeader {
	BString	name;
	BString	value;
};


class HpackDecoder {
public:
								HpackDecoder();

			// Decode one header block into `out` (appended). Returns B_OK, or
			// B_NOT_SUPPORTED if a Huffman-coded string is encountered (until
			// the Huffman decoder lands), or B_BAD_DATA on malformed input.
			status_t			Decode(const uint8* buf, size_t len,
									std::vector<HpackHeader>& out);

			void				SetMaxDynamicSize(size_t maxSize);

private:
			bool				_DecodeInteger(const uint8* buf, size_t len,
									size_t& pos, uint8 prefixBits,
									uint32& outValue);
			status_t			_DecodeString(const uint8* buf, size_t len,
									size_t& pos, BString& out);
			bool				_Lookup(uint32 index, HpackHeader& out) const;
			void				_AddDynamic(const HpackHeader& header);
			void				_Evict();

			std::vector<HpackHeader>	fDynamic;	// newest at front
			size_t						fDynamicSize;
			size_t						fMaxDynamicSize;
};


class HpackEncoder {
public:
			// Append the HPACK encoding of (name, value) to `out`. Names are
			// matched case-sensitively against the static table (HTTP/2 headers
			// are lowercase); a full name+value match emits an indexed field, a
			// name-only match a literal with indexed name, otherwise a fully
			// literal field. Values are emitted raw (no Huffman).
	static	void				AddHeader(std::vector<uint8>& out,
									const char* name, const char* value);

private:
	static	void				_EncodeInteger(std::vector<uint8>& out,
									uint8 prefixBits, uint8 prefixMask,
									uint32 value);
	static	void				_EncodeRawString(std::vector<uint8>& out,
									const char* str, size_t len);
};

}	// namespace ts


#endif	// TS_HPACK_H
