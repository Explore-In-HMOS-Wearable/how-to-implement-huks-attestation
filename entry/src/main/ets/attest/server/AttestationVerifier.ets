import { cert } from '@kit.DeviceCertificateKit';
import { resourceManager } from '@kit.LocalizationKit';
import { util } from '@kit.ArkTS';
import { BusinessError } from '@kit.BasicServicesKit';
import { extractChallenge, findExtensionValue, ATTESTATION_EXT_OID } from './Asn1';

// The pinned Huawei root CA (PEM) bundled at entry/src/main/resources/rawfile.
const ROOT_CA_RAWFILE: string = 'huawei_attest_root_ca.pem';

function toBytes(value: string): Uint8Array {
  return new util.TextEncoder().encodeInto(value);
}

function toHex(bytes: Uint8Array): string {
  let out: string = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

export interface VerificationReport {
  chainTrusted: boolean;
  challengeMatched: boolean;
  publicKeyPreview: string;
  detail: string;
}

/**
 * Server-side verification, simulated on the device.
 *
 * Given the attestation certificate chain from HuksAttestation, this reproduces
 * what a backend does:
 *   1. Parse the X.509 chain.
 *   2. Validate it against the pinned Huawei root CA (proves genuine TEE hardware).
 *   3. Read the challenge from the leaf's attestation extension (proves freshness).
 *   4. Extract the leaf public key (a server would store it for the user).
 */
export class AttestationVerifier {
  /** Runs the full server-side check against the attestation chain. */
  static async verify(
    pemChain: string[],
    expectedChallenge: Uint8Array,
    resMgr: resourceManager.ResourceManager
  ): Promise<VerificationReport> {
    const report: VerificationReport = {
      chainTrusted: false,
      challengeMatched: false,
      publicKeyPreview: '',
      detail: ''
    };
    if (pemChain.length === 0) {
      report.detail = 'Empty certificate chain — run attestation first.';
      return report;
    }

    let certs: cert.X509Cert[];
    try {
      certs = await AttestationVerifier.parseChain(pemChain);
    } catch (err) {
      report.detail = `Certificate parsing failed: ${(err as BusinessError).message}`;
      return report;
    }

    const leaf: cert.X509Cert = certs[0];
    const leafDer: Uint8Array = AttestationVerifier.pemToDer(pemChain[0]);
    report.chainTrusted = await AttestationVerifier.isChainTrusted(certs, resMgr);
    report.challengeMatched = AttestationVerifier.challengeMatches(leafDer, expectedChallenge);
    report.publicKeyPreview = AttestationVerifier.leafPublicKeyPreview(leaf);
    report.detail = report.chainTrusted
      ? (report.challengeMatched ? 'Attestation verified.' : 'Chain is genuine but the challenge did not match.')
      : 'Certificate chain is not trusted.';
    return report;
  }

  /** Parses each PEM certificate into an X509Cert object. */
  private static async parseChain(pemChain: string[]): Promise<cert.X509Cert[]> {
    const certs: cert.X509Cert[] = [];
    try {
      for (let i = 0; i < pemChain.length; i++) {
        const blob: cert.EncodingBlob = { data: toBytes(pemChain[i]), encodingFormat: cert.EncodingFormat.FORMAT_PEM };
        certs.push(await cert.createX509Cert(blob));
      }
    } catch (err) {
      const e = err as BusinessError;
      throw new Error(`${e.code} - ${e.message}`);
    }
    return certs;
  }

  /** Validates the chain against the pinned Huawei root CA (the trust anchor). */
  private static async isChainTrusted(certs: cert.X509Cert[],
    resMgr: resourceManager.ResourceManager): Promise<boolean> {
    try {
      // Load the pinned root CA (PEM) from the bundled rawfile — this is the trust anchor.
      const rootPem: Uint8Array = resMgr.getRawFileContentSync(ROOT_CA_RAWFILE);
      const rootBlob: cert.EncodingBlob = { data: rootPem, encodingFormat: cert.EncodingFormat.FORMAT_PEM };
      const root: cert.X509Cert = await cert.createX509Cert(rootBlob);
      const chain: cert.X509CertChain = cert.createX509CertChain(certs);
      const params: cert.CertChainValidationParameters = { trustAnchors: [{ CACert: root }] };
      await chain.validate(params);
      return true;
    } catch (err) {
      const e = err as BusinessError;
      console.error(`AttestationVerifier chain validation failed: ${e.code} - ${e.message}`);
      return false;
    }
  }

  /** Decodes a PEM certificate to its raw DER bytes (base64 body between the markers). */
  private static pemToDer(pem: string): Uint8Array {
    const body: string = pem
      .replace('-----BEGIN CERTIFICATE-----', '')
      .replace('-----END CERTIFICATE-----', '')
      .replace(/\s/g, '');
    return new util.Base64Helper().decodeSync(body);
  }

  /** Reads the challenge from the leaf's attestation extension and compares it. */
  private static challengeMatches(certDer: Uint8Array, expected: Uint8Array): boolean {
    const extValue: Uint8Array | undefined = findExtensionValue(certDer, ATTESTATION_EXT_OID);
    if (extValue === undefined) {
      console.error('AttestationVerifier: attestation extension not found in certificate');
      return false;
    }
    const challenge: Uint8Array | undefined = extractChallenge(extValue);
    if (challenge === undefined) {
      console.error(`AttestationVerifier: challenge claim not found (ext ${extValue.length}B: ${toHex(extValue.slice(0, 24))}…)`);
      return false;
    }
    const matched: boolean = bytesEqual(challenge, expected);
    if (!matched) {
      console.error(`AttestationVerifier: challenge mismatch cert=${toHex(challenge)} expected=${toHex(expected)}`);
    }
    return matched;
  }

  /** Returns a short hex preview of the leaf certificate's public key. */
  private static leafPublicKeyPreview(leaf: cert.X509Cert): string {
    try {
      const encoded: Uint8Array = leaf.getPublicKey().getEncoded().data;
      return `${toHex(encoded.slice(0, 8))}... (${encoded.length} bytes)`;
    } catch (err) {
      const e = err as BusinessError;
      console.error(`AttestationVerifier public key read failed: ${e.code} - ${e.message}`);
      return '';
    }
  }
}
