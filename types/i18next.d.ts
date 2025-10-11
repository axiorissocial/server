import 'express-serve-static-core';
import type { TFunction } from 'i18next';

declare module 'express-serve-static-core' {
  interface Request {
    t: TFunction;
    language: string;
    csrfToken?: () => string;
  }
}
