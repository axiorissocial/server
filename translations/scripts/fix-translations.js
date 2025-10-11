import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const TRANSLATIONS_DIR = path.join(__dirname, '../locales');

function getLocales() {
  return fs.readdirSync(TRANSLATIONS_DIR)
    .filter(item => fs.statSync(path.join(TRANSLATIONS_DIR, item)).isDirectory())
    .sort();
}

function loadTranslations(locale) {
  const filePath = path.join(TRANSLATIONS_DIR, locale, 'common.json');
  if (!fs.existsSync(filePath)) {
    console.warn(`Warning: ${filePath} does not exist`);
    return {};
  }
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    console.error(`Error loading ${filePath}:`, error.message);
    return {};
  }
}

function saveTranslations(locale, data) {
  const filePath = path.join(TRANSLATIONS_DIR, locale, 'common.json');
  const dir = path.dirname(filePath);
  
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

function getAllKeys(obj, prefix = '') {
  let keys = [];
  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      keys.push(...getAllKeys(value, fullKey));
    } else {
      keys.push(fullKey);
    }
  }
  return keys;
}

function getValueByPath(obj, path) {
  return path.split('.').reduce((current, key) => current?.[key], obj);
}

function setValueByPath(obj, path, value) {
  const keys = path.split('.');
  const lastKey = keys.pop();
  const target = keys.reduce((current, key) => {
    if (!(key in current)) {
      current[key] = {};
    }
    return current[key];
  }, obj);
  target[lastKey] = value;
}

function removeExtraKeys(translations, validKeys) {
  const validKeySet = new Set(validKeys);
  
  function cleanObject(obj, prefix = '') {
    const keysToDelete = [];
    
    for (const [key, value] of Object.entries(obj)) {
      const fullKey = prefix ? `${prefix}.${key}` : key;
      
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        cleanObject(value, fullKey);
        if (Object.keys(value).length === 0) {
          keysToDelete.push(key);
        }
      } else {
        if (!validKeySet.has(fullKey)) {
          keysToDelete.push(key);
        }
      }
    }
    
    keysToDelete.forEach(key => delete obj[key]);
  }
  
  cleanObject(translations);
  return translations;
}

function getTranslationForKey(englishValue, targetLocale, existingValue = null) {
  if (existingValue && typeof existingValue === 'string' && existingValue.startsWith('TODO_TRANSLATE: ')) {
    const manualTranslation = existingValue.substring('TODO_TRANSLATE: '.length);
    if (manualTranslation && manualTranslation !== englishValue) {
      console.log(`Using manual translation for "${englishValue.substring(0, 30)}..."`);
      return manualTranslation;
    }
  }
  
  console.log(`Manual translation needed for "${englishValue.substring(0, 30)}..."`);
  return `TODO_TRANSLATE: ${englishValue}`;
}

function fixTranslations() {
  console.log('Fixing translations...\n');
  
  const locales = getLocales();
  const englishTranslations = loadTranslations('en');
  const englishKeys = getAllKeys(englishTranslations);
  
  for (const locale of locales) {
    if (locale === 'en') continue;
    
    console.log(`Processing ${locale}...`);
    let translations = loadTranslations(locale);
    let hasChanges = false;
    let addedKeys = 0;
    let removedKeys = 0;
    
    const currentKeys = getAllKeys(translations);
    const extraKeysBefore = currentKeys.filter(key => !englishKeys.includes(key));
    
    if (extraKeysBefore.length > 0) {
      translations = removeExtraKeys(translations, englishKeys);
      removedKeys = extraKeysBefore.length;
      hasChanges = true;
      console.log(`Removed ${removedKeys} extra keys`);
    }
    
    for (const key of englishKeys) {
      const englishValue = getValueByPath(englishTranslations, key);
      const existingValue = getValueByPath(translations, key);
      
      if (!existingValue || (typeof existingValue === 'string' && existingValue.startsWith('TODO_TRANSLATE:'))) {
        const translatedValue = getTranslationForKey(englishValue, locale, existingValue);
        setValueByPath(translations, key, translatedValue);
        addedKeys++;
        hasChanges = true;
      }
    }
    
    if (hasChanges) {
      saveTranslations(locale, translations);
      console.log(`Updated ${locale}: +${addedKeys} translations, -${removedKeys} extra keys`);
    } else {
      console.log(`No changes needed for ${locale}`);
    }
    
    console.log('');
  }
  
  console.log('Translation fix complete!');
}

process.on('unhandledRejection', (error) => {
  console.error('Unhandled promise rejection:', error);
  process.exit(1);
});

try {
  fixTranslations();
} catch (error) {
  console.error('Error fixing translations:', error);
  process.exit(1);
}