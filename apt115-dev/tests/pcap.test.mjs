// Tests de pcap — disector PCAP/PCAPNG.
//
// Verificación con ORÁCULO horneada: los fixtures se generaron con **scapy 2.7.0**
// (wrpcap LE/BE/nanosec + PcapNgWriter) y se cruzaron contra rdpcap y tcpdump
// durante el desarrollo. Se embeben en base64 para que `npm test` corra offline,
// sin dependencias Python. Cada fixture lleva los MISMOS 6 paquetes:
//   0: DNS query   A? evil.example.com         (UDP :51000→53)
//   1: DNS resp    A 185.220.101.4             (UDP :53→51000)
//   2: HTTP GET    /malware/payload.bin Host c2.badguy.net  (TCP :44000→80)
//   3: TLS ClientHello SNI login.secure-bank.com (TCP :44002→443)
//   4: IPv6 TCP SYN 2001:db8::5 → 2001:db8::1  (:40000→22)
//   5: VLAN(100) ICMP echo 10.0.0.9 → 10.0.0.1

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pcap as P } from '../src/tools/pcap.js';

const FIX = {
  le_us: '1MOyoQIABAAAAAAAAAAAAP//AAABAAAA2CIuatGOCgBMAAAATAAAAP///////wAVXaGHFwgARQAAPgABAABAEWCaCgAABQgICAjHOAA1ACrJeQAAAQAAAQAAAAAAAARldmlsB2V4YW1wbGUDY29tAAABAAHYIi5qXZAKAGwAAABsAAAA////////ABVdoYcXCABFAABeAAEAAEARYHoICAgICgAABQA1xzgASta1AACBAAABAAEAAAAABGV2aWwHZXhhbXBsZQNjb20AAAEAAQRldmlsB2V4YW1wbGUDY29tAAABAAEAAAAAAAS53GUE2CIuar2RCgCJAAAAiQAAAP///////wAVXaGHFwgARQAAewABAABABjqdCgAABV242CKr4ABQAAAAAAAAAABQGCAAfy0AAEdFVCAvbWFsd2FyZS9wYXlsb2FkLmJpbiBIVFRQLzEuMQ0KSG9zdDogYzIuYmFkZ3V5Lm5ldA0KVXNlci1BZ2VudDogRXZpbEJvdC8xLjANCg0K2CIuaomSCgCIAAAAiAAAAP///////wAVXaGHFwgARQAAegABAABABghoCgAABWgQAAGr4gG7AAAAAAAAAABQGCAA4BYAABYDAQBNAQAASQMDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAITAQEAAB4AAAAaABgAABVsb2dpbi5zZWN1cmUtYmFuay5jb23YIi5qLpMKAEoAAABKAAAA////////AAAAAAAAht1gAAAAABQGQCABDbgAAAAAAAAAAAAAAAUgAQ24AAAAAAAAAAAAAAABnEAAFgAAAAAAAAAAUAIgAJgUAADYIi5qr5MKAC4AAAAuAAAA////////ABVdoYcXgQAAZAgARQAAHAABAABAAWbXCgAACQoAAAEIAPf/AAAAAA==',
  le_ns: 'TTyyoQIABAAAAAAAAAAAAP//AAABAAAA2CIuanXfPSlMAAAATAAAAP///////wAVXaGHFwgARQAAPgABAABAEWCaCgAABQgICAjHOAA1ACrJeQAAAQAAAQAAAAAAAARldmlsB2V4YW1wbGUDY29tAAABAAHYIi5qP+xDKWwAAABsAAAA////////ABVdoYcXCABFAABeAAEAAEARYHoICAgICgAABQA1xzgASta1AACBAAABAAEAAAAABGV2aWwHZXhhbXBsZQNjb20AAAEAAQRldmlsB2V4YW1wbGUDY29tAAABAAEAAAAAAAS53GUE2CIuauFKSSmJAAAAiQAAAP///////wAVXaGHFwgARQAAewABAABABjqdCgAABV242CKr4ABQAAAAAAAAAABQGCAAfy0AAEdFVCAvbWFsd2FyZS9wYXlsb2FkLmJpbiBIVFRQLzEuMQ0KSG9zdDogYzIuYmFkZ3V5Lm5ldA0KVXNlci1BZ2VudDogRXZpbEJvdC8xLjANCg0K2CIuajtmTCmIAAAAiAAAAP///////wAVXaGHFwgARQAAegABAABABghoCgAABWgQAAGr4gG7AAAAAAAAAABQGCAA4BYAABYDAQBNAQAASQMDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAITAQEAAB4AAAAaABgAABVsb2dpbi5zZWN1cmUtYmFuay5jb23YIi5qtOpOKUoAAABKAAAA////////AAAAAAAAht1gAAAAABQGQCABDbgAAAAAAAAAAAAAAAUgAQ24AAAAAAAAAAAAAAABnEAAFgAAAAAAAAAAUAIgAJgUAADYIi5qWOVQKS4AAAAuAAAA////////ABVdoYcXgQAAZAgARQAAHAABAABAAWbXCgAACQoAAAEIAPf/AAAAAA==',
  be_us: 'obLD1AACAAQAAAAAAAAAAAAA//8AAAABai4i2AAKjtEAAABMAAAATP///////wAVXaGHFwgARQAAPgABAABAEWCaCgAABQgICAjHOAA1ACrJeQAAAQAAAQAAAAAAAARldmlsB2V4YW1wbGUDY29tAAABAAFqLiLYAAqQXQAAAGwAAABs////////ABVdoYcXCABFAABeAAEAAEARYHoICAgICgAABQA1xzgASta1AACBAAABAAEAAAAABGV2aWwHZXhhbXBsZQNjb20AAAEAAQRldmlsB2V4YW1wbGUDY29tAAABAAEAAAAAAAS53GUEai4i2AAKkb0AAACJAAAAif///////wAVXaGHFwgARQAAewABAABABjqdCgAABV242CKr4ABQAAAAAAAAAABQGCAAfy0AAEdFVCAvbWFsd2FyZS9wYXlsb2FkLmJpbiBIVFRQLzEuMQ0KSG9zdDogYzIuYmFkZ3V5Lm5ldA0KVXNlci1BZ2VudDogRXZpbEJvdC8xLjANCg0Kai4i2AAKkokAAACIAAAAiP///////wAVXaGHFwgARQAAegABAABABghoCgAABWgQAAGr4gG7AAAAAAAAAABQGCAA4BYAABYDAQBNAQAASQMDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAITAQEAAB4AAAAaABgAABVsb2dpbi5zZWN1cmUtYmFuay5jb21qLiLYAAqTLgAAAEoAAABK////////AAAAAAAAht1gAAAAABQGQCABDbgAAAAAAAAAAAAAAAUgAQ24AAAAAAAAAAAAAAABnEAAFgAAAAAAAAAAUAIgAJgUAABqLiLYAAqTrwAAAC4AAAAu////////ABVdoYcXgQAAZAgARQAAHAABAABAAWbXCgAACQoAAAEIAPf/AAAAAA==',
  png: 'Cg0NChwAAABNPCsaAQAAAP//////////HAAAAAEAAAAUAAAAAQAAAAAABAAUAAAABgAAAGwAAAAAAAAALlQGAND0NntMAAAATAAAAP///////wAVXaGHFwgARQAAPgABAABAEWCaCgAABQgICAjHOAA1ACrJeQAAAQAAAQAAAAAAAARldmlsB2V4YW1wbGUDY29tAAABAAFsAAAABgAAAIwAAAAAAAAALlQGAF32NntsAAAAbAAAAP///////wAVXaGHFwgARQAAXgABAABAEWB6CAgICAoAAAUANcc4AErWtQAAgQAAAQABAAAAAARldmlsB2V4YW1wbGUDY29tAAABAAEEZXZpbAdleGFtcGxlA2NvbQAAAQABAAAAAAAEudxlBIwAAAAGAAAArAAAAAAAAAAuVAYAvfc2e4kAAACJAAAA////////ABVdoYcXCABFAAB7AAEAAEAGOp0KAAAFXbjYIqvgAFAAAAAAAAAAAFAYIAB/LQAAR0VUIC9tYWx3YXJlL3BheWxvYWQuYmluIEhUVFAvMS4xDQpIb3N0OiBjMi5iYWRndXkubmV0DQpVc2VyLUFnZW50OiBFdmlsQm90LzEuMA0KDQoAAACsAAAABgAAAKgAAAAAAAAALlQGAIj4NnuIAAAAiAAAAP///////wAVXaGHFwgARQAAegABAABABghoCgAABWgQAAGr4gG7AAAAAAAAAABQGCAA4BYAABYDAQBNAQAASQMDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAITAQEAAB4AAAAaABgAABVsb2dpbi5zZWN1cmUtYmFuay5jb22oAAAABgAAAGwAAAAAAAAALlQGAC35NntKAAAASgAAAP///////wAAAAAAAIbdYAAAAAAUBkAgAQ24AAAAAAAAAAAAAAAFIAENuAAAAAAAAAAAAAAAAZxAABYAAAAAAAAAAFACIACYFAAAAABsAAAABgAAAFAAAAAAAAAALlQGAK/5NnsuAAAALgAAAP///////wAVXaGHF4EAAGQIAEUAABwAAQAAQAFm1woAAAkKAAABCAD3/wAAAAAAAFAAAAA=',
};
const bytes = (k) => new Uint8Array(Buffer.from(FIX[k], 'base64'));

test('detect: PCAP LE/BE/ns + PCAPNG', () => {
  assert.deepEqual(P.detect(bytes('le_us')), { fmt: 'pcap', le: true, nano: false });
  assert.deepEqual(P.detect(bytes('le_ns')), { fmt: 'pcap', le: true, nano: true });
  assert.deepEqual(P.detect(bytes('be_us')), { fmt: 'pcap', le: false, nano: false });
  assert.deepEqual(P.detect(bytes('png')), { fmt: 'pcapng' });
  assert.equal(P.detect(new Uint8Array([1, 2, 3])), null);
});

// El conteo de paquetes y las 5-tuplas DEBEN coincidir con scapy/rdpcap en los 4 formatos.
for (const k of ['le_us', 'le_ns', 'be_us', 'png']) {
  test(`${k}: conteo + 5-tuplas vs scapy`, () => {
    const p = P.parse(bytes(k));
    assert.equal(p.packetCount, 6, 'conteo de paquetes');
    assert.equal(p.linkTypeName, 'ETHERNET');
    const pk = p.packets;
    // pkt0: DNS query UDP
    assert.equal(pk[0].l3, 'IPv4'); assert.equal(pk[0].proto, 'UDP');
    assert.equal(pk[0].src, '10.0.0.5'); assert.equal(pk[0].dst, '8.8.8.8');
    assert.equal(pk[0].sport, 51000); assert.equal(pk[0].dport, 53);
    // pkt2: HTTP TCP
    assert.equal(pk[2].proto, 'TCP'); assert.equal(pk[2].dport, 80);
    // pkt4: IPv6 SYN
    assert.equal(pk[4].l3, 'IPv6');
    assert.equal(pk[4].src, '2001:db8::5'); assert.equal(pk[4].dst, '2001:db8::1');
    assert.equal(pk[4].dport, 22);
    // pkt5: VLAN ICMP
    assert.equal(pk[5].proto, 'ICMP'); assert.equal(pk[5].src, '10.0.0.9');
  });
}

test('formato y byte order reportados', () => {
  assert.equal(P.parse(bytes('le_us')).format, 'pcap');
  assert.equal(P.parse(bytes('le_us')).byteOrder, 'little-endian');
  assert.equal(P.parse(bytes('be_us')).byteOrder, 'big-endian');
  assert.equal(P.parse(bytes('le_ns')).tsRes, 'nanosegundos');
  assert.equal(P.parse(bytes('png')).format, 'pcapng');
});

test('DNS: query + respuesta A', () => {
  const s = P.parse(bytes('le_us')).summary;
  assert.equal(s.dns.length, 2);
  const q = s.dns.find(d => !d.qr), r = s.dns.find(d => d.qr);
  assert.equal(q.qname, 'evil.example.com');
  assert.equal(q.qtype, 'A');
  assert.equal(r.qname, 'evil.example.com');
  assert.equal(r.answers.find(a => a.type === 'A').data, '185.220.101.4');
});

test('HTTP: método + host + URI + user-agent', () => {
  const s = P.parse(bytes('le_us')).summary;
  assert.equal(s.http.length, 1);
  const h = s.http[0];
  assert.equal(h.method, 'GET');
  assert.equal(h.host, 'c2.badguy.net');
  assert.equal(h.uri, '/malware/payload.bin');
  assert.equal(h.ua, 'EvilBot/1.0');
});

test('TLS: SNI del ClientHello', () => {
  const s = P.parse(bytes('le_us')).summary;
  assert.equal(s.tls.length, 1);
  assert.equal(s.tls[0].sni, 'login.secure-bank.com');
});

test('conversaciones + protocolos', () => {
  const s = P.parse(bytes('le_us')).summary;
  assert.equal(s.protoStats.TCP, 3);
  assert.equal(s.protoStats.UDP, 2);
  assert.equal(s.protoStats.ICMP, 1);
  // DNS query+response colapsan en UNA conversación (clave canónica bidireccional)
  assert.equal(s.conversations.length, 5);
  const dnsConv = s.conversations.find(c => c.proto === 'UDP');
  assert.equal(dnsConv.packets, 2);
});

test('IOCs estructurales del tráfico', () => {
  const ind = P.parse(bytes('le_us')).summary.indicators;
  assert.ok(ind.ips.includes('185.220.101.4'));
  assert.ok(ind.ips.includes('2001:db8::1'));
  assert.ok(ind.domains.includes('evil.example.com'));
  assert.ok(ind.domains.includes('c2.badguy.net'));
  assert.ok(ind.domains.includes('login.secure-bank.com'));
  assert.ok(ind.urls.includes('http://c2.badguy.net/malware/payload.bin'));
});

test('ipv6: compresión RFC 5952', () => {
  // 2001:db8:0:0:0:0:0:1 → 2001:db8::1
  const b = new Uint8Array(16);
  b[0] = 0x20; b[1] = 0x01; b[2] = 0x0d; b[3] = 0xb8; b[15] = 1;
  assert.equal(P.ipv6(b, 0), '2001:db8::1');
  const z = new Uint8Array(16); // todo cero → ::
  assert.equal(P.ipv6(z, 0), '::');
});

test('parse de basura → null', () => {
  assert.equal(P.parse(new Uint8Array([0, 1, 2, 3, 4, 5])), null);
});
