/*
 * Copyright 2026 atomozero. All rights reserved.
 * Distributed under the terms of the MIT License.
 *
 * Offline self-test for the Tailscale backend's deterministic modules: crypto
 * against published vectors, wire codecs by round-trip, and the netmap/peer/DNS
 * logic against fixtures. No network -- the live checks (control handshake,
 * STUN, DERP) are exercised separately. Build + run with the Makefile here.
 */
#include <cstdio>
#include <cstring>

#include "NaClBox.h"
#include "PeerPath.h"
#include "TSControl.h"
#include "TSDisco.h"
#include "TSHpack.h"
#include "TSIdentity.h"
#include "TSMagicDns.h"
#include "TSNetmap.h"
#include "TSNoise.h"
#include "TSPeerSet.h"
#include "TSStun.h"
#include "WGPeer.h"
#include "WireGuardCrypto.h"

using namespace ts;

static int sFail = 0;
static int sPass = 0;
#define CHECK(cond, msg) do { \
	if (cond) { sPass++; } \
	else { sFail++; printf("  FAIL: %s\n", msg); } \
} while (0)

static int nib(char c) {
	if (c>='0'&&c<='9') return c-'0';
	if (c>='a'&&c<='f') return c-'a'+10;
	if (c>='A'&&c<='F') return c-'A'+10;
	return -1;
}
static size_t unhex(const char* h, uint8* out) {
	size_t n=0; for (; h[0]&&h[1]; h+=2) out[n++]=(nib(h[0])<<4)|nib(h[1]); return n;
}


static void
test_identity_hex()
{
	uint8 a[32]; for (int i=0;i<32;i++) a[i]=(uint8)(i*7+1);
	BString h = TSIdentity::ToHex(a, 32);
	uint8 b[32];
	CHECK(h.Length()==64, "hex length 64");
	CHECK(TSIdentity::FromHex(h.String(), b, 32) && memcmp(a,b,32)==0, "hex round-trip");
	CHECK(!TSIdentity::FromHex("zz", b, 1), "reject non-hex");
	// X25519 public is deterministic from private.
	uint8 priv[32],pub[32],pub2[32];
	CHECK(wg::DhGenerate(priv,pub) && wg::DhPublic(priv,pub2) && memcmp(pub,pub2,32)==0,
		"X25519 pub deterministic");
}


static void
test_nacl_box()
{
	uint8 alicesk[32],bobpk[32],nonce[24],firstkey[32];
	unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", alicesk);
	unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", bobpk);
	unhex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37", nonce);
	unhex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389", firstkey);
	uint8 key[32];
	CHECK(BoxBeforeNm(key,bobpk,alicesk) && memcmp(key,firstkey,32)==0, "NaCl beforenm vector");
	uint8 msg[131];
	unhex("be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc"
	      "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31"
	      "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde"
	      "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705", msg);
	uint8 expected[147];
	unhex("f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce"
	      "48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972"
	      "71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae"
	      "90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3"
	      "7973f622a43d14a6599b1f654cb45a74e355a5", expected);
	uint8 sealed[147], opened[131];
	CHECK(BoxSeal(sealed,msg,131,nonce,bobpk,alicesk) && memcmp(sealed,expected,147)==0,
		"NaCl box canonical ciphertext");
	CHECK(BoxOpen(opened,sealed,147,nonce,bobpk,alicesk) && memcmp(opened,msg,131)==0,
		"NaCl box open");
	sealed[80]^=1;
	CHECK(!BoxOpen(opened,sealed,147,nonce,bobpk,alicesk), "NaCl box tamper reject");
}


static void
test_hpack()
{
	const uint8 c31[] = {0x82,0x86,0x84,0x41,0x0f,0x77,0x77,0x77,0x2e,0x65,0x78,
		0x61,0x6d,0x70,0x6c,0x65,0x2e,0x63,0x6f,0x6d};
	HpackDecoder d;
	std::vector<HpackHeader> out;
	CHECK(d.Decode(c31,sizeof(c31),out)==B_OK && out.size()==4
		&& out[3].name==":authority" && out[3].value=="www.example.com",
		"HPACK C.3.1 (no huffman)");
	const uint8 c41[] = {0x82,0x86,0x84,0x41,0x8c,0xf1,0xe3,0xc2,0xe5,0xf2,0x3a,
		0x6b,0xa0,0xab,0x90,0xf4,0xff};
	HpackDecoder d2; std::vector<HpackHeader> o2;
	CHECK(d2.Decode(c41,sizeof(c41),o2)==B_OK && o2.size()==4
		&& o2[3].value=="www.example.com", "HPACK C.4.1 (huffman)");
	// encoder -> decoder round-trip.
	std::vector<uint8> enc;
	HpackEncoder::AddHeader(enc, ":method", "POST");
	HpackEncoder::AddHeader(enc, ":path", "/machine/register");
	HpackDecoder d3; std::vector<HpackHeader> o3;
	CHECK(d3.Decode(enc.data(),enc.size(),o3)==B_OK && o3.size()==2
		&& o3[1].value=="/machine/register", "HPACK encode round-trip");
}


static void
test_noise()
{
	uint8 isPriv[32],isPub[32],rsPriv[32],rsPub[32];
	wg::DhGenerate(isPriv,isPub); wg::DhGenerate(rsPriv,rsPub);
	NoiseIK init,resp;
	init.InitInitiator(isPriv,isPub,rsPub,"p",1);
	resp.InitResponder(rsPriv,rsPub,"p",1);
	uint8 m1[128]; ssize_t n1=init.WriteMessage1("hi",2,m1,sizeof(m1));
	uint8 g1[128]; ssize_t r1=resp.ReadMessage1(m1,n1,g1,sizeof(g1));
	uint8 m2[128]; ssize_t n2=resp.WriteMessage2("yo",2,m2,sizeof(m2));
	uint8 g2[128]; ssize_t r2=init.ReadMessage2(m2,n2,g2,sizeof(g2));
	NoiseTransportKeys ik,rk; init.Split(ik); resp.Split(rk);
	CHECK(r1==2 && r2==2 && memcmp(g1,"hi",2)==0 && memcmp(g2,"yo",2)==0,
		"Noise IK payloads round-trip");
	CHECK(memcmp(ik.sendKey,rk.sendKey,32)==0 && memcmp(ik.recvKey,rk.recvKey,32)==0,
		"Noise IK transport keys agree");
	CHECK(memcmp(init.HandshakeHash(),resp.HandshakeHash(),32)==0, "Noise handshake hash agrees");
}


static void
test_stun_disco()
{
	// STUN XOR-MAPPED-ADDRESS parse.
	uint8 tx[12]; for (int i=0;i<12;i++) tx[i]=(uint8)(i+1);
	uint8 resp[32]; memset(resp,0,sizeof(resp));
	resp[0]=0x01;resp[1]=0x01;resp[3]=0x0c;
	resp[4]=0x21;resp[5]=0x12;resp[6]=0xa4;resp[7]=0x42;
	memcpy(resp+8,tx,12);
	resp[21]=0x20;resp[23]=0x08;resp[25]=0x01;
	uint16 xp=(uint16)(0x1234^0x2112); resp[26]=(uint8)(xp>>8);resp[27]=(uint8)(xp&0xff);
	resp[28]=(uint8)(1^0x21);resp[29]=(uint8)(2^0x12);resp[30]=(uint8)(3^0xa4);resp[31]=(uint8)(4^0x42);
	BString ip; uint16 port=0;
	CHECK(StunParseResponse(resp,32,tx,ip,port) && ip=="1.2.3.4" && port==0x1234,
		"STUN XOR-MAPPED-ADDRESS parse");

	// disco Ping seal/open round-trip.
	uint8 dPriv[32],dPub[32]; wg::DhGenerate(dPriv,dPub);
	uint8 nk[32]; for (int i=0;i<32;i++) nk[i]=(uint8)i;
	uint8 ping[64]; size_t pl=EncodePing(ping,tx,nk);
	uint8 pkt[256]; ssize_t pn=DiscoSeal(pkt,sizeof(pkt),dPub,dPriv,dPub,ping,pl);
	uint8 sender[32],payload[128]; ssize_t plen=DiscoOpen(pkt,pn,dPriv,sender,payload,sizeof(payload));
	DiscoPing dp;
	CHECK(plen>0 && memcmp(sender,dPub,32)==0 && DecodePing(payload,plen,dp)
		&& memcmp(dp.txid,tx,12)==0 && dp.hasNodeKey, "disco Ping seal/open");
}


static void
test_wgpeer()
{
	uint8 key[32]; wg::RandomBytes(key,32);
	WGPeer peer; peer.SetTransport(key,key,0x11223344);
	uint8 ip[20]; memset(ip,0,20); ip[0]=0x45; ip[3]=0x14;
	uint8 msg[128]; size_t n=peer.Encapsulate(ip,20,msg);
	uint8 out[128]; ssize_t d=peer.Decapsulate(msg,n,out);
	CHECK(n==64 && d==20 && memcmp(out,ip,20)==0, "WGPeer type-4 round-trip");
	CHECK(peer.Decapsulate(msg,n,out)<0, "WGPeer replay reject");
	// handshake initiation format.
	uint8 op[32],opub[32],pp[32],ppub[32]; wg::DhGenerate(op,opub); wg::DhGenerate(pp,ppub);
	WGPeer h; uint8 init[148];
	CHECK(h.BuildInitiation(op,ppub,init)==148 && init[0]==1, "WGPeer initiation 148/type1");
	uint8 bad[92]; memset(bad,0,92); bad[0]=2;
	CHECK(!h.ConsumeResponse(bad,92), "WGPeer bad response reject");

	// Full Noise IKpsk2 handshake, initiator <-> responder, then bidirectional
	// transport data -- exercises the responder path (ConsumeInitiation /
	// BuildResponse) and the swapped transport-key derivation.
	uint8 iPriv[32],iPub[32],rPriv[32],rPub[32];
	wg::DhGenerate(iPriv,iPub); wg::DhGenerate(rPriv,rPub);
	WGPeer ini, res;
	uint8 m1[148];
	CHECK(ini.BuildInitiation(iPriv,rPub,m1)==148, "handshake: initiation built");
	uint8 recov[32];
	CHECK(WGPeer::RecoverInitiatorStatic(rPriv,m1,148,recov)
		&& memcmp(recov,iPub,32)==0, "responder recovers initiator static");
	CHECK(res.ConsumeInitiation(rPriv,m1,148), "responder consumes initiation");
	uint8 m2[92];
	CHECK(res.BuildResponse(m2)==92 && m2[0]==2, "responder builds type-2 response");
	CHECK(ini.ConsumeResponse(m2,92) && ini.HasKeys(), "initiator consumes response");
	CHECK(res.HasKeys(), "responder has transport keys");
	uint8 ip2[20]; memset(ip2,0,20); ip2[0]=0x45; ip2[3]=0x14; ip2[19]=0x99;
	uint8 e1[128]; size_t en1=ini.Encapsulate(ip2,20,e1);
	uint8 dout[128]; ssize_t dd1=res.Decapsulate(e1,en1,dout);
	CHECK(dd1==20 && memcmp(dout,ip2,20)==0, "handshake initiator->responder data");
	uint8 e2[128]; size_t en2=res.Encapsulate(ip2,20,e2);
	ssize_t dd2=ini.Decapsulate(e2,en2,dout);
	CHECK(dd2==20 && memcmp(dout,ip2,20)==0, "handshake responder->initiator data");
	// A wrong responder static must not decrypt the initiator's static.
	uint8 wPriv[32],wPub[32]; wg::DhGenerate(wPriv,wPub);
	CHECK(!WGPeer::RecoverInitiatorStatic(wPriv,m1,148,recov),
		"responder rejects initiation not addressed to it");
}


static void
test_netmap_peers_dns_route()
{
	const char* json =
	"{\"Node\":{\"Addresses\":[\"100.64.7.1/32\"]},\"Peers\":["
	  "{\"Key\":\"nodekey:aabbccdd\",\"AllowedIPs\":[\"100.64.7.6/32\"],"
	    "\"Endpoints\":[\"1.1.1.1:41641\"],\"DERP\":\"127.3.3.40:2\","
	    "\"Online\":true,\"Hostinfo\":{\"Hostname\":\"laptop\"}},"
	  "{\"Key\":\"nodekey:99887766\",\"AllowedIPs\":[\"100.64.0.0/16\"],"
	    "\"Hostinfo\":{\"Hostname\":\"router\"}}"
	"],\"DNSConfig\":{\"Domains\":[\"tail1.ts.net\"]},"
	  "\"DERPMap\":{\"Regions\":{\"2\":{\"RegionID\":2,\"RegionCode\":\"sfo\","
	    "\"Nodes\":[{\"HostName\":\"derp2.tailscale.com\"}]}}}}";
	TSNetmap nm;
	CHECK(nm.Parse(json,strlen(json)), "netmap parse");
	CHECK(nm.SelfIPv4()=="100.64.7.1" && nm.Peers().size()==2, "netmap self+peers");
	CHECK(nm.DerpRegionById(2)!=NULL && nm.Dns().domains.size()==1, "netmap DERP+DNS");

	TSPeerSet set; int a=0; set.Update(nm,&a,NULL,NULL);
	CHECK(set.Count()==2 && a==2, "peerset add");
	// longest-prefix routing: 100.64.7.6 is the /32 (laptop) not the /16 (router).
	ManagedPeer* p = set.FindByAllowedIP("100.64.7.6");
	CHECK(p!=NULL && p->hostname=="laptop", "route /32 beats /16");
	p = set.FindByAllowedIP("100.64.9.9");
	CHECK(p!=NULL && p->hostname=="router", "route /16 subnet");
	CHECK(set.FindByAllowedIP("8.8.8.8")==NULL, "route unrouted");

	MagicDns dns; dns.LoadFromNetmap(nm);
	uint8 q[256],r[512]; ssize_t qn=DnsBuildQuery("laptop.tail1.ts.net",1,q,sizeof(q));
	ssize_t rn=dns.Resolve(q,qn,r,sizeof(r));
	CHECK(rn>0 && r[rn-4]==100 && r[rn-3]==64 && r[rn-2]==7 && r[rn-1]==6,
		"MagicDNS laptop -> 100.64.7.6");
}


static void
test_pathstate()
{
	PeerPath p; p.UseDerp();
	CHECK(p.Mode()==PATH_DERP, "path starts DERP");
	p.UpgradeToDirect("1.2.3.4:41641",1000000);
	CHECK(p.Mode()==PATH_DIRECT, "path upgrades direct");
	p.UseDerp();
	CHECK(p.Mode()==PATH_DIRECT, "UseDerp doesn't downgrade");
	CHECK(p.Evaluate(10000000,5000000)==PATH_DERP, "path falls back when stale");
}


static void
test_control_framing()
{
	uint8 m1[96]; for (int i=0;i<96;i++) m1[i]=(uint8)i;
	uint8 frame[128];
	ssize_t n = EncodeInitiation(m1,96,144,frame,sizeof(frame));
	CHECK(n==(ssize_t)kInitiationMsgLen && frame[0]==0x00 && frame[1]==0x90
		&& frame[2]==1 && frame[4]==0x60, "ts2021 initiation header (v144)");
	uint8 ck[32];
	CHECK(ParseControlKey("{\"publicKey\":\"mkey:7d2792f9c98d753d2042471536801949"
		"104c247f95eac770f8fb321595e2173b\"}", ck) && ck[0]==0x7d,
		"parse control mkey");
}


int main()
{
	printf("Tailscale backend self-test (offline)\n");
	test_identity_hex();
	test_nacl_box();
	test_hpack();
	test_noise();
	test_stun_disco();
	test_wgpeer();
	test_netmap_peers_dns_route();
	test_pathstate();
	test_control_framing();
	printf("---\n%d passed, %d failed\n", sPass, sFail);
	return sFail == 0 ? 0 : 1;
}
