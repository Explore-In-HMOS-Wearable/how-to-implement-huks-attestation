import { resourceManager } from '@kit.LocalizationKit';
import { util } from '@kit.ArkTS';
import { AttestationVerifier, VerificationReport } from './AttestationVerifier';

/** Simulated attestation backend (server side). */
export class AttestationServer {
  private issuedNonce: Uint8Array = new Uint8Array();
  private noncePreview: string = '';

  /** Issues a fresh random nonce and caches it for the next verify(). */
  requestNonce(): Uint8Array {
    const nonce: string = util.generateRandomUUID(true);
    this.issuedNonce = new util.TextEncoder().encodeInto(nonce.replaceAll('-', ''));
    this.noncePreview = nonce.substring(0, 8);
    return this.issuedNonce;
  }

  /** Short preview of the last issued nonce, for display. */
  lastNoncePreview(): string {
    return this.noncePreview;
  }

  /** Verifies the chain and checks its challenge against the nonce this server issued. */
  verify(pemChain: string[], resMgr: resourceManager.ResourceManager): Promise<VerificationReport> {
    return AttestationVerifier.verify(pemChain, this.issuedNonce, resMgr);
  }
}
