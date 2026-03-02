// SPDX-License-Identifier: MIT

// Test entry point — exposes crypto functions on window for Playwright tests.

import {
  base62Encode,
  base62Decode,
  deriveKeys,
  computeConfirmation,
  EncryptedChannel,
  exportPublicKey,
  importPublicKey,
  encryptFileInfo,
  decryptFileInfo,
} from "./crypto";
import { SHA256 } from "./sha256";

(window as any).__cryptoTest = {
  base62Encode,
  base62Decode,
  deriveKeys,
  computeConfirmation,
  EncryptedChannel,
  exportPublicKey,
  importPublicKey,
  encryptFileInfo,
  decryptFileInfo,
  SHA256,
};
