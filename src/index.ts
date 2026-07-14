'use strict';
import 'dotenv/config';
import express, { Request, Response } from 'express';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { CmsPkcs12Service } from './service';

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
const service = new CmsPkcs12Service();

app.post('/api/cms/sign-pkcs12', async (_req: Request, res: Response) => {
  const inputPath = process.env.SOLIDSIGN_BATCH_INPUT_PATH ?? '';
  const outputPath = process.env.SOLIDSIGN_BATCH_OUTPUT_PATH ?? '';
  const certId = process.env.SOLIDSIGN_CERT_ID ?? '';
  if (!fs.existsSync(inputPath) || !fs.statSync(inputPath).isDirectory())
    return res.status(400).json({ error: `Invalid input path: ${inputPath}` });
  const allFiles = fs.readdirSync(inputPath).filter(f => fs.statSync(path.join(inputPath, f)).isFile()).map(f => path.join(inputPath, f));
  if (!allFiles.length) return res.json({ message: `No files found in ${inputPath}` });
  const result = await service.signPkcs12(allFiles, certId, outputPath);
  return result ? res.json({ message: `ZIP generated at: ${result}` }) : res.status(500).json({ error: 'Failed.' });
});

app.post('/api/cms/sign/form', upload.fields([{ name: 'document' }]),
  async (req: Request, res: Response) => {
    const files = req.files as Record<string, Express.Multer.File[]>;
    const b = req.body as Record<string, string>;
    const zip = await service.signPkcs12Form(b.authorization, b.baseUrl, b.pfxCode,
      files['document'] ?? [], b.profile, b.hashAlgorithm, b.signaturePackaging, b.policyVersion);
    if (zip) { res.setHeader('Content-Type','application/zip'); res.setHeader('Content-Disposition','attachment; filename=signed_cms.zip'); return res.send(zip); }
    return res.status(500).json({ error: 'Failed.' });
  });

const PORT = Number(process.env.PORT ?? 8091);
app.listen(PORT, () => console.info(`SolidSign CMS PKCS12 (TS) running on port ${PORT}`));
