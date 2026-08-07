/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 */
#include "TSJson.h"

#include <stdlib.h>
#include <string.h>


namespace ts {

JsonValue::JsonValue()
	:
	type(JSON_NULL),
	boolValue(false),
	numberValue(0.0)
{
}


const JsonValue*
JsonValue::Find(const char* key) const
{
	if (type != JSON_OBJECT || key == NULL)
		return NULL;
	for (size_t i = 0; i < objectValue.size(); i++) {
		if (objectValue[i].first == key)
			return &objectValue[i].second;
	}
	return NULL;
}


const char*
JsonValue::AsString(const char* fallback) const
{
	return type == JSON_STRING ? stringValue.String() : fallback;
}


bool
JsonValue::AsBool(bool fallback) const
{
	return type == JSON_BOOL ? boolValue : fallback;
}


double
JsonValue::AsNumber(double fallback) const
{
	return type == JSON_NUMBER ? numberValue : fallback;
}


// --- recursive-descent parser ----------------------------------------------

namespace {

struct Cursor {
	const char*	p;
	const char*	end;
};

void
skip_ws(Cursor& c)
{
	while (c.p < c.end) {
		char ch = *c.p;
		if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r')
			c.p++;
		else
			break;
	}
}

bool parse_value(Cursor& c, JsonValue& out);

void
append_utf8(BString& s, uint32 cp)
{
	if (cp < 0x80) {
		s << (char)cp;
	} else if (cp < 0x800) {
		s << (char)(0xc0 | (cp >> 6)) << (char)(0x80 | (cp & 0x3f));
	} else {
		s << (char)(0xe0 | (cp >> 12))
			<< (char)(0x80 | ((cp >> 6) & 0x3f))
			<< (char)(0x80 | (cp & 0x3f));
	}
}

int
hex4(const char* p)
{
	int v = 0;
	for (int i = 0; i < 4; i++) {
		char ch = p[i];
		int d;
		if (ch >= '0' && ch <= '9') d = ch - '0';
		else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
		else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
		else return -1;
		v = (v << 4) | d;
	}
	return v;
}

bool
parse_string(Cursor& c, BString& out)
{
	if (c.p >= c.end || *c.p != '"')
		return false;
	c.p++;
	out = "";
	while (c.p < c.end) {
		char ch = *c.p++;
		if (ch == '"')
			return true;
		if (ch == '\\') {
			if (c.p >= c.end)
				return false;
			char esc = *c.p++;
			switch (esc) {
				case '"': out << '"'; break;
				case '\\': out << '\\'; break;
				case '/': out << '/'; break;
				case 'b': out << '\b'; break;
				case 'f': out << '\f'; break;
				case 'n': out << '\n'; break;
				case 'r': out << '\r'; break;
				case 't': out << '\t'; break;
				case 'u':
				{
					if (c.end - c.p < 4)
						return false;
					int cp = hex4(c.p);
					if (cp < 0)
						return false;
					c.p += 4;
					// Surrogate pair.
					if (cp >= 0xd800 && cp <= 0xdbff && c.end - c.p >= 6
							&& c.p[0] == '\\' && c.p[1] == 'u') {
						int lo = hex4(c.p + 2);
						if (lo >= 0xdc00 && lo <= 0xdfff) {
							c.p += 6;
							uint32 full = 0x10000
								+ (((uint32)(cp - 0xd800)) << 10)
								+ (uint32)(lo - 0xdc00);
							if (full < 0x80) out << (char)full;
							else if (full < 0x800)
								out << (char)(0xc0 | (full >> 6))
									<< (char)(0x80 | (full & 0x3f));
							else if (full < 0x10000)
								append_utf8(out, full);
							else
								out << (char)(0xf0 | (full >> 18))
									<< (char)(0x80 | ((full >> 12) & 0x3f))
									<< (char)(0x80 | ((full >> 6) & 0x3f))
									<< (char)(0x80 | (full & 0x3f));
							break;
						}
					}
					append_utf8(out, (uint32)cp);
					break;
				}
				default:
					return false;
			}
		} else {
			out << ch;
		}
	}
	return false;	// unterminated
}

bool
parse_number(Cursor& c, JsonValue& out)
{
	const char* start = c.p;
	while (c.p < c.end) {
		char ch = *c.p;
		if ((ch >= '0' && ch <= '9') || ch == '-' || ch == '+' || ch == '.'
				|| ch == 'e' || ch == 'E')
			c.p++;
		else
			break;
	}
	if (c.p == start)
		return false;
	BString tmp(start, c.p - start);
	out.type = JSON_NUMBER;
	out.numberValue = strtod(tmp.String(), NULL);
	return true;
}

bool
parse_object(Cursor& c, JsonValue& out)
{
	c.p++;	// consume '{'
	out.type = JSON_OBJECT;
	skip_ws(c);
	if (c.p < c.end && *c.p == '}') { c.p++; return true; }
	for (;;) {
		skip_ws(c);
		BString key;
		if (!parse_string(c, key))
			return false;
		skip_ws(c);
		if (c.p >= c.end || *c.p != ':')
			return false;
		c.p++;
		skip_ws(c);
		JsonValue val;
		if (!parse_value(c, val))
			return false;
		bool dup = false;
		for (size_t i = 0; i < out.objectValue.size(); i++) {
			if (out.objectValue[i].first == key) { dup = true; break; }
		}
		if (!dup)
			out.objectValue.push_back(std::make_pair(key, val));
		skip_ws(c);
		if (c.p >= c.end)
			return false;
		if (*c.p == ',') { c.p++; continue; }
		if (*c.p == '}') { c.p++; return true; }
		return false;
	}
}

bool
parse_array(Cursor& c, JsonValue& out)
{
	c.p++;	// consume '['
	out.type = JSON_ARRAY;
	skip_ws(c);
	if (c.p < c.end && *c.p == ']') { c.p++; return true; }
	for (;;) {
		skip_ws(c);
		JsonValue val;
		if (!parse_value(c, val))
			return false;
		out.arrayValue.push_back(val);
		skip_ws(c);
		if (c.p >= c.end)
			return false;
		if (*c.p == ',') { c.p++; continue; }
		if (*c.p == ']') { c.p++; return true; }
		return false;
	}
}

bool
parse_value(Cursor& c, JsonValue& out)
{
	skip_ws(c);
	if (c.p >= c.end)
		return false;
	char ch = *c.p;
	if (ch == '{')
		return parse_object(c, out);
	if (ch == '[')
		return parse_array(c, out);
	if (ch == '"') {
		out.type = JSON_STRING;
		return parse_string(c, out.stringValue);
	}
	if (ch == 't') {
		if (c.end - c.p >= 4 && strncmp(c.p, "true", 4) == 0) {
			c.p += 4; out.type = JSON_BOOL; out.boolValue = true; return true;
		}
		return false;
	}
	if (ch == 'f') {
		if (c.end - c.p >= 5 && strncmp(c.p, "false", 5) == 0) {
			c.p += 5; out.type = JSON_BOOL; out.boolValue = false; return true;
		}
		return false;
	}
	if (ch == 'n') {
		if (c.end - c.p >= 4 && strncmp(c.p, "null", 4) == 0) {
			c.p += 4; out.type = JSON_NULL; return true;
		}
		return false;
	}
	return parse_number(c, out);
}

}	// anonymous namespace


bool
JsonParser::Parse(const char* text, size_t len, JsonValue& out)
{
	if (text == NULL)
		return false;
	Cursor c;
	c.p = text;
	c.end = text + len;
	if (!parse_value(c, out))
		return false;
	skip_ws(c);
	return true;	// trailing bytes tolerated
}

}	// namespace ts
