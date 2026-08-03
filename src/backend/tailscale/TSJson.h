/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#ifndef TS_JSON_H
#define TS_JSON_H


#include <stddef.h>

#include <String.h>
#include <SupportDefs.h>

#include <utility>
#include <vector>


// A small, allocation-simple JSON DOM parser. The control protocol's
// MapResponse is deeply nested (Node, Peers[], each with Addresses/AllowedIPs/
// Endpoints/DERP, plus DNSConfig and DERPMap), which a flat string scan can't
// navigate safely, so we parse into a value tree and walk it. Scope is a
// pragmatic subset of RFC 8259: objects, arrays, strings (with the standard
// escapes and \uXXXX for the basic multilingual plane), numbers (as double),
// booleans and null. Duplicate object keys keep the first.
namespace ts {

enum JsonType {
	JSON_NULL,
	JSON_BOOL,
	JSON_NUMBER,
	JSON_STRING,
	JSON_ARRAY,
	JSON_OBJECT
};


class JsonValue {
public:
								JsonValue();

			JsonType			type;
			bool				boolValue;
			double				numberValue;
			BString				stringValue;
			std::vector<JsonValue>						arrayValue;
			std::vector<std::pair<BString, JsonValue> >	objectValue;

			bool				IsObject() const { return type == JSON_OBJECT; }
			bool				IsArray() const { return type == JSON_ARRAY; }
			bool				IsString() const { return type == JSON_STRING; }

			// Object member lookup (case-sensitive). NULL if absent / not an
			// object.
			const JsonValue*	Find(const char* key) const;

			// Convenience typed accessors with defaults.
			const char*			AsString(const char* fallback = "") const;
			bool				AsBool(bool fallback = false) const;
			double				AsNumber(double fallback = 0.0) const;
};


class JsonParser {
public:
	// Parse `len` bytes of JSON text into `out`. Returns true on success.
	static	bool				Parse(const char* text, size_t len,
									JsonValue& out);
};

}	// namespace ts


#endif	// TS_JSON_H
