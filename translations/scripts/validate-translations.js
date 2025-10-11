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

function validateTranslations() {
  console.log('Validating translations...\n');
  
  const locales = getLocales();
  const englishTranslations = loadTranslations('en');
  const englishKeys = new Set(getAllKeys(englishTranslations));
  
  let hasErrors = false;
  const stats = {};
  
  for (const locale of locales) {
    console.log(`Checking ${locale}...`);
    const translations = loadTranslations(locale);
    const keys = new Set(getAllKeys(translations));
    
    const missingKeys = [...englishKeys].filter(key => !keys.has(key));
    const extraKeys = [...keys].filter(key => !englishKeys.has(key));
    const todoTranslateKeys = [];
    
    for (const key of keys) {
      const value = getValueByPath(translations, key);
      if (typeof value === 'string' && value.startsWith('TODO_TRANSLATE:')) {
        todoTranslateKeys.push(key);
      }
    }
    
    stats[locale] = {
      total: englishKeys.size,
      translated: keys.size - todoTranslateKeys.length,
      missing: missingKeys.length,
      extra: extraKeys.length,
      todoTranslate: todoTranslateKeys.length,
      coverage: Math.round(((keys.size - todoTranslateKeys.length) / englishKeys.size) * 100)
    };
    
    if (missingKeys.length > 0) {
      console.log(`Missing ${missingKeys.length} keys:`);
      missingKeys.slice(0, 10).forEach(key => console.log(`    - ${key}`));
      if (missingKeys.length > 10) {
        console.log(`... and ${missingKeys.length - 10} more`);
      }
      hasErrors = true;
    }
    
    if (extraKeys.length > 0) {
      console.log(`Extra ${extraKeys.length} keys:`);
      extraKeys.slice(0, 5).forEach(key => console.log(`    - ${key}`));
      if (extraKeys.length > 5) {
        console.log(`... and ${extraKeys.length - 5} more`);
      }
    }
    
    if (todoTranslateKeys.length > 0) {
      console.log(`${todoTranslateKeys.length} TODO_TRANSLATE strings:`);
      todoTranslateKeys.slice(0, 5).forEach(key => console.log(`    - ${key}`));
      if (todoTranslateKeys.length > 5) {
        console.log(`... and ${todoTranslateKeys.length - 5} more`);
      }
    }
    
    console.log(`Coverage: ${stats[locale].coverage}%\n`);
  }
  
  console.log('\nTranslation Coverage Summary:');
  console.log('┌─────────┬─────────┬───────────┬─────────┬───────┬──────────┬──────────┐');
  console.log('│ Locale  │ Total   │ Translated│ Missing │ Extra │ TODO     │ Coverage │');
  console.log('├─────────┼─────────┼───────────┼─────────┼───────┼──────────┼──────────┤');
  
  for (const locale of locales) {
    const s = stats[locale];
    console.log(`│ ${locale.padEnd(7)} │ ${s.total.toString().padStart(7)} │ ${s.translated.toString().padStart(9)} │ ${s.missing.toString().padStart(7)} │ ${s.extra.toString().padStart(5)} │ ${s.todoTranslate.toString().padStart(8)} │ ${(s.coverage + '%').padStart(8)} │`);
  }
  
  console.log('└─────────┴─────────┴───────────┴─────────┴───────┴──────────┴──────────┘');
  
  if (hasErrors) {
    console.log('\n❌ Validation failed! Please fix the missing translations.');
    process.exit(1);
  } else {
    console.log('\n✅ All translations are valid!');
  }
}

validateTranslations();