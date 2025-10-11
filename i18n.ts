import path from 'path';
import fs from 'fs';
import i18next from 'i18next';
import Backend from 'i18next-fs-backend';
import * as i18nextMiddleware from 'i18next-http-middleware';

const localesDir = path.join(process.cwd(), 'translations/locales');

const discoverLanguages = () => {
  try {
    const entries = fs.readdirSync(localesDir, { withFileTypes: true });
    const languages = entries
      .filter(entry => entry.isDirectory())
      .map(entry => entry.name)
      .filter(lang => fs.existsSync(path.join(localesDir, lang, 'common.json')));

    return languages.length > 0 ? languages : ['en'];
  } catch (error) {
    console.error('Unable to read locales directory:', error);
    return ['en'];
  }
};

const availableLanguages = discoverLanguages();

if (!i18next.isInitialized) {
  i18next
    .use(Backend)
    .use(i18nextMiddleware.LanguageDetector)
    .init({
      backend: {
        loadPath: path.join(localesDir, '{{lng}}/{{ns}}.json'),
      },
      fallbackLng: 'en',
      preload: availableLanguages,
      supportedLngs: availableLanguages,
      ns: ['common'],
      defaultNS: 'common',
      detection: {
        order: ['cookie', 'header', 'querystring'],
        caches: false,
      },
      interpolation: {
        escapeValue: false,
      },
      returnNull: false,
    })
    .then(() => {
      console.log('i18next server initialized');
    })
    .catch(error => {
      console.error('Error initializing i18next:', error);
    });
}

const getAvailableLanguages = () => [...availableLanguages];

export { i18next, i18nextMiddleware, getAvailableLanguages };
