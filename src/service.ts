'use strict';
import axios from 'axios';
import FormData from 'form-data';
import JSZip from 'jszip';
import fs from 'fs';
import path from 'path';

interface SignLink { rel: string; href: string; }
interface SignResponse { documents: { links: SignLink[] }[]; }

export class CmsPkcs12Service {
  private readonly baseUrl = (process.env.SOLIDSIGN_API_BASE_URL ?? '').replace(/\/$/, '');
  private readonly authorization = process.env.SOLIDSIGN_API_AUTHORIZATION ?? '';
  private readonly profile = process.env.SOLIDSIGN_SIG_PROFILE ?? 'ADRB';
  private readonly hashAlgorithm = process.env.SOLIDSIGN_SIG_HASH_ALGORITHM ?? 'SHA256';
  private readonly signaturePackaging = process.env.SOLIDSIGN_SIG_PACKAGING ?? 'ENVELOPING';
  private readonly policyVersion = process.env.SOLIDSIGN_SIG_POLICY_VERSION ?? '';

  async signPkcs12(files: string[], certId: string, outputDir: string): Promise<string | null> {
    const form = new FormData();
    files.forEach((f, i) => form.append(`document[${i}]`, fs.createReadStream(f), { filename: path.basename(f) }));
    form.append('pfxCode', certId);
    form.append('profile', this.profile); form.append('hashAlgorithm', this.hashAlgorithm);
    form.append('signaturePackaging', this.signaturePackaging);
    if (this.policyVersion) form.append('policyVersion', this.policyVersion);
    try {
      const r = await axios.post<SignResponse>(`${this.baseUrl}/solidsign/dsig/cms/sign-pkcs12`, form,
        { headers: { Authorization: this.authorization, ...form.getHeaders() }, timeout: 120000 });
      const zip = await this.downloadAndZip(r.data, files.map(f => path.basename(f)), this.authorization);
      fs.mkdirSync(outputDir, { recursive: true });
      const out = path.join(outputDir, `signed_cms_pkcs12_${Date.now()}.zip`);
      fs.writeFileSync(out, zip); return out;
    } catch (err) { this.logError('CAdES PKCS12', err); return null; }
  }

  async signPkcs12Form(authorization: string, baseUrl: string, pfxCode: string,
    documents: Express.Multer.File[], profile?: string, hashAlgorithm?: string,
    signaturePackaging?: string, policyVersion?: string): Promise<Buffer | null> {
    const form = new FormData();
    documents.forEach((d, i) => form.append(`document[${i}]`, d.buffer, { filename: d.originalname }));
    form.append('pfxCode', pfxCode);
    if (profile)            form.append('profile', profile);
    if (hashAlgorithm)      form.append('hashAlgorithm', hashAlgorithm);
    if (signaturePackaging) form.append('signaturePackaging', signaturePackaging);
    if (policyVersion)      form.append('policyVersion', policyVersion);
    try {
      const r = await axios.post<SignResponse>(`${baseUrl.replace(/\/$/, '')}/solidsign/dsig/cms/sign-pkcs12`, form,
        { headers: { Authorization: authorization, ...form.getHeaders() }, timeout: 120000 });
      return this.downloadAndZip(r.data, documents.map(d => d.originalname), authorization);
    } catch (err) { this.logError('CAdES PKCS12 form', err); return null; }
  }

  private async downloadAndZip(resp: SignResponse, names: string[], auth: string): Promise<Buffer> {
    const zip = new JSZip();
    await Promise.all((resp.documents ?? []).map(async (doc, i) => {
      const link = (doc as any)._links?.self ?? doc.links?.find(l => l.rel === 'self'); if (!link) return;
      const r = await axios.get<ArrayBuffer>(link.href, { headers: { Authorization: auth }, responseType: 'arraybuffer', timeout: 120000 });
      if (r.status === 200) zip.file(`signed_${names[i]}`, r.data);
    }));
    return zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
  }

  private logError(ctx: string, err: unknown): void {
    if (axios.isAxiosError(err)) console.error(`SolidSign error ${err.response?.status} [${ctx}]`);
    else console.error(`Error [${ctx}]: ${(err as Error).message}`);
  }
}
