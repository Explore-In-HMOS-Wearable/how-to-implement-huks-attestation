import { huks } from '@kit.UniversalKeystoreKit';
import { util } from '@kit.ArkTS';
import { BusinessError } from '@kit.BasicServicesKit';

const KEY_ALIAS: string = 'tee-attest-demo-key';

function toBytes(value: string): Uint8Array {
  return new util.TextEncoder().encodeInto(value);
}

/**
 * Device-side TEE key attestation with HUKS (Universal Keystore Kit).
 *
 * The device generates an asymmetric key inside secure hardware (TEE) and asks
 * HUKS to attest it. HUKS returns an X.509 certificate chain, rooted at a Huawei
 * CA, that a server (here, AttestationVerifier) checks to prove the key really
 * lives in genuine Huawei TEE hardware and that this attestation is fresh.
 *
 * Anonymous attestation (anonAttestKeyItem) is used because it needs no special
 * system permission, unlike attestKeyItem (which requires ohos.permission.ATTEST_KEY).
 */
export class HuksAttestation {
  /** Generates a fresh TEE key and returns its attestation certificate chain (PEM). */
  static async attest(challenge: Uint8Array): Promise<string[]> {
    await HuksAttestation.generateFreshKey();

    const properties: huks.HuksParam[] = [
      { tag: huks.HuksTag.HUKS_TAG_ATTESTATION_CHALLENGE, value: challenge },
      { tag: huks.HuksTag.HUKS_TAG_ATTESTATION_ID_ALIAS, value: toBytes(KEY_ALIAS) }
    ];
    const options: huks.HuksOptions = { properties };

    try {
      const result = await huks.anonAttestKeyItem(KEY_ALIAS, options);
      const chain = (result.certChains ?? []) as string[];
      console.info(`HuksAttestation: extracted ${chain.length} certificate(s)`);
      for (let i = 0; i < chain.length; i++) {
        console.info(`HuksAttestation: certificate[${i}]:\n${chain[i]}`);
      }
      return chain;
    } catch (err) {
      const e = err as BusinessError;
      throw new Error(`attestation failed: ${e.code} - ${e.message}`);
    }
  }

  /**Anonymous attestation requires a NEWLY generated key. (reusing one makes it fail)
   * So any previous key is deleted and regenerated before every attestation. */
  private static async generateFreshKey(): Promise<void> {
    try {
      await huks.deleteKeyItem(KEY_ALIAS, { properties: [] });
    } catch (err) {
      // The key may not exist yet — safe to ignore.
    }

    const properties: huks.HuksParam[] = [
      { tag: huks.HuksTag.HUKS_TAG_ALGORITHM, value: huks.HuksKeyAlg.HUKS_ALG_ECC },
      { tag: huks.HuksTag.HUKS_TAG_KEY_SIZE, value: huks.HuksKeySize.HUKS_ECC_KEY_SIZE_256 },
      {
        tag: huks.HuksTag.HUKS_TAG_PURPOSE,
        value: huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN | huks.HuksKeyPurpose.HUKS_KEY_PURPOSE_VERIFY
      },
      { tag: huks.HuksTag.HUKS_TAG_DIGEST, value: huks.HuksKeyDigest.HUKS_DIGEST_SHA256 }
    ];
    try {
      await huks.generateKeyItem(KEY_ALIAS, { properties });
    } catch (err) {
      const e = err as BusinessError;
      throw new Error(`key generation failed: ${e.code} - ${e.message}`);
    }
  }
}
