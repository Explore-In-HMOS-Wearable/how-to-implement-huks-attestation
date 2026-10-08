/*
 * Minimal DER (ASN.1) reader, this walks the tag-length-value structure by hand to stay
 * dependency-free. A prod server should use a full ASN.1 library;
 *
 * Huawei attestation extension (OID 1|3|6|1|4|1|2011|2|376|1|3):
 *   SEQUENCE {
 *     version   INTEGER,
 *     claim*    SEQUENCE { securityLevel INTEGER, type OID, value ANY }
 *   }
 * The challenge is the claim whose type OID is 1|3|6|1|4|1|2011|2|376|2|1|4. A
 * full server would also read the appId (…x.x.x) and key-manager id (…x.x.x.x).
 */

// DER encoding of OID 1|3|6|1|4|1|2011|2|376|2|1|4 (the attestation challenge claim).
const CHALLENGE_OID: number[] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x02, 0x01, 0x04];

// DER encoding of OID 1|3|6|1|4|1|2011|2|376|1|3 (the Huawei key-attestation extension itself).
export const ATTESTATION_EXT_OID: number[] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x5b, 0x02, 0x82, 0x78, 0x01, 0x03];

const TAG_OCTET_STRING: number = 0x04;
const TAG_SEQUENCE: number = 0x30;
const TAG_OID: number = 0x06;
const TAG_INTEGER: number = 0x02;
const TAG_BOOLEAN: number = 0x01;
const TAG_EXTENSIONS: number = 0xa3;

interface Tlv {
  tag: number;
  contentStart: number;
  contentEnd: number;
}

// Reads one tag-length-value triple starting at offset (supports long-form length).
function readTlv(bytes: Uint8Array, offset: number): Tlv {
  const tag: number = bytes[offset];
  let cursor: number = offset + 1;
  let length: number = bytes[cursor];
  cursor += 1;
  if (length >= 0x80) {
    const lengthBytes: number = length & 0x7f;
    length = 0;
    for (let i = 0; i < lengthBytes; i++) {
      length = (length * 256) + bytes[cursor];
      cursor += 1;
    }
  }
  return { tag, contentStart: cursor, contentEnd: cursor + length };
}

function oidEquals(bytes: Uint8Array, oid: Tlv, expected: number[]): boolean {
  if (oid.contentEnd - oid.contentStart !== expected.length) {
    return false;
  }
  for (let i = 0; i < expected.length; i++) {
    if (bytes[oid.contentStart + i] !== expected[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Walks an X.509 certificate (DER) to the extension with the given OID and returns its
 * extnValue OCTET STRING content (the inner DER), or undefined if the extension is absent.
 * Used instead of the native cert.getEntry, which rejects this private OID with error 401.
 */
export function findExtensionValue(certDer: Uint8Array, oid: number[]): Uint8Array | undefined {
  const certificate: Tlv = readTlv(certDer, 0);
  if (certificate.tag !== TAG_SEQUENCE) {
    return undefined;
  }
  const tbs: Tlv = readTlv(certDer, certificate.contentStart);
  if (tbs.tag !== TAG_SEQUENCE) {
    return undefined;
  }

  // Extensions sit inside a [3] EXPLICIT tag; scan the TBSCertificate fields for it.
  let fieldOffset: number = tbs.contentStart;
  let extensions: Tlv | undefined = undefined;
  while (fieldOffset < tbs.contentEnd) {
    const field: Tlv = readTlv(certDer, fieldOffset);
    fieldOffset = field.contentEnd;
    if (field.tag === TAG_EXTENSIONS) {
      extensions = readTlv(certDer, field.contentStart);
      break;
    }
  }
  if (extensions === undefined || extensions.tag !== TAG_SEQUENCE) {
    return undefined;
  }

  let offset: number = extensions.contentStart;
  while (offset < extensions.contentEnd) {
    const extension: Tlv = readTlv(certDer, offset);
    offset = extension.contentEnd;
    if (extension.tag !== TAG_SEQUENCE) {
      continue;
    }
    const extnId: Tlv = readTlv(certDer, extension.contentStart);
    if (extnId.tag !== TAG_OID || !oidEquals(certDer, extnId, oid)) {
      continue;
    }
    // extnID is followed by an optional critical BOOLEAN, then the extnValue OCTET STRING.
    let next: Tlv = readTlv(certDer, extnId.contentEnd);
    if (next.tag === TAG_BOOLEAN) {
      next = readTlv(certDer, next.contentEnd);
    }
    if (next.tag !== TAG_OCTET_STRING) {
      return undefined;
    }
    return certDer.slice(next.contentStart, next.contentEnd);
  }
  return undefined;
}

/** Extracts the attestation challenge from the extension value, or undefined. */
export function extractChallenge(extensionValue: Uint8Array): Uint8Array | undefined {
  let root: Tlv = readTlv(extensionValue, 0);
  // Some accessors wrap the value in an OCTET STRING — unwrap it first.
  if (root.tag === TAG_OCTET_STRING) {
    root = readTlv(extensionValue, root.contentStart);
  }
  if (root.tag !== TAG_SEQUENCE) {
    return undefined;
  }

  // The leading version is DEFAULT v1, so DER may omit it — skip it only when a
  // real INTEGER is present, otherwise the first claim (the challenge) is dropped.
  const first: Tlv = readTlv(extensionValue, root.contentStart);
  let offset: number = first.tag === TAG_INTEGER ? first.contentEnd : root.contentStart;
  while (offset < root.contentEnd) {
    const claim: Tlv = readTlv(extensionValue, offset);
    offset = claim.contentEnd;
    if (claim.tag !== TAG_SEQUENCE) {
      continue;
    }
    const securityLevel: Tlv = readTlv(extensionValue, claim.contentStart);
    const type: Tlv = readTlv(extensionValue, securityLevel.contentEnd);
    if (type.tag === TAG_OID && oidEquals(extensionValue, type, CHALLENGE_OID)) {
      const value: Tlv = readTlv(extensionValue, type.contentEnd);
      return extensionValue.slice(value.contentStart, value.contentEnd);
    }
  }
  return undefined;
}