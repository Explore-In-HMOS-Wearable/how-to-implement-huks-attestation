import { HuksAttestation } from '../attest/app/HuksAttestation';
import { AttestationServer } from '../attest/server/AttestationServer';
import { common } from '@kit.AbilityKit';

@Entry
@ComponentV2
struct Index {
  private static readonly TAG: string = 'TeeAttestationGuide';
  private server: AttestationServer = new AttestationServer();
  private chain: string[] = [];
  @Local status: string = 'Ready. Attest on the device, then verify.';
  @Local busy: boolean = false;

  build() {
    Column({ space: 5 }) {
      Text('TEE Attestation with HUKS')
        .fontSize(13)
        .fontWeight(FontWeight.Bold)
        .maxLines(2)
        .width('80%')
        .textAlign(TextAlign.Center)

      Button('1 - Attest (device)')
        .width('80%')
        .fontSize(12)
        .enabled(!this.busy)
        .onClick(() => {
          this.runAttestation();
        })

      Button('2 - Verify (server)')
        .width('80%')
        .fontSize(12)
        .enabled(!this.busy)
        .onClick(() => {
          this.runVerification();
        })

      Text(this.status)
        .fontSize(11)
        .fontColor(Color.Gray)
        .width('80%')
        .textAlign(TextAlign.Center)
    }
    .width('100%')
    .height('100%')
    .justifyContent(FlexAlign.Center)
    .padding(10)
  }

  // Device side: get a nonce from the backend, then HUKS attests the TEE key with it.
  private async runAttestation(): Promise<void> {
    this.busy = true;
    try {
      const nonce: Uint8Array = this.server.requestNonce();
      this.status = `Got nonce ${this.server.lastNoncePreview()}… attesting on device…`;
      this.chain = await HuksAttestation.attest(nonce);
      this.status = this.chain.length > 0
        ? `Attested with nonce ${this.server.lastNoncePreview()}: ${this.chain.length} certs. Now Verify.`
        : 'Attestation returned no certificates.';
    } catch (err) {
      const e = err as Error;
      console.error(`${Index.TAG} attestation failed: ${e.message}`);
      this.status = 'Attestation failed (needs a real TEE device).';
    } finally {
      this.busy = false;
    }
  }

  // Server side (on device): validate the chain and check the nonce it issued.
  private async runVerification(): Promise<void> {
    if (this.chain.length === 0) {
      this.status = 'Run attestation first.';
      return;
    }
    this.busy = true;
    this.status = 'Server verifying certificate chain…';
    try {
      const resMgr = (this.getUIContext().getHostContext() as common.Context).resourceManager;
      const report = await this.server.verify(this.chain, resMgr);
      this.status =
        `Chain trusted: ${report.chainTrusted ? 'yes' : 'no'}\nNonce matched: ${report.challengeMatched ? 'yes' :
          'no'}\nKey: ${report.publicKeyPreview.length > 0 ? report.publicKeyPreview : 'n/a'}\n${report.detail}`;
    } catch (err) {
      const e = err as Error;
      console.error(`${Index.TAG} verification failed: ${e.message}`);
      this.status = 'Verification error.';
    } finally {
      this.busy = false;
    }
  }
}