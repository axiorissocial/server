import leo from 'leo-profanity';

try {
  (leo as any).loadDictionary('en');
} catch (err) {}

const list = () => leo.list();

const HIGH_SEVERITY_RAW = process.env.HIGH_SEVERITY_PROFANITY || '';
const HIGH_SEVERITY_LIST = HIGH_SEVERITY_RAW.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

export const containsHighSeverity = (text?: string | null): boolean => {
  if (!text) return false;
  const lower = String(text).toLowerCase();
  for (const bad of HIGH_SEVERITY_LIST) {
    if (!bad) continue;
    if (lower.includes(bad)) return true;
  }

  const compact = lower.replace(/[^a-z0-9]+/g, '');
  if (!compact) return false;
  for (const bad of HIGH_SEVERITY_LIST) {
    const cleanedBad = bad.replace(/[^a-z0-9]+/g, '');
    if (!cleanedBad) continue;
    if (compact.includes(cleanedBad)) return true;
  }
  return false;
};

export const containsProfanity = (text?: string | null): boolean => {
  if (!text) return false;
  try {
    return leo.check(String(text));
  } catch (err) {
    return false;
  }
};

export const containsProfanityStrict = (text?: string | null): boolean => {
  if (!text) return false;
  const lower = String(text).toLowerCase();
  if (containsProfanity(lower)) return true;

  const compact = lower.replace(/[^a-z0-9]+/g, '');
  if (!compact) return false;

  try {
    for (const bad of list()) {
      const cleanedBad = String(bad).toLowerCase().replace(/[^a-z0-9]+/g, '');
      if (!cleanedBad) continue;
      if (compact.includes(cleanedBad)) return true;
    }
  } catch (err) {
    return false;
  }

  return false;
};

export const censor = (text?: string | null): string => {
  if (!text) return '';
  try {
    return leo.clean(String(text));
  } catch (err) {
    return String(text);
  }
};

export default {
  containsProfanity,
  containsProfanityStrict,
  censor,
};

export const containsProfanityForPosts = (text?: string | null): boolean => {
  if (!text) return false;
  const lower = String(text).toLowerCase();

  if (containsHighSeverity(lower)) return true;

  const compact = lower.replace(/[^a-z0-9]+/g, ' ');
  const words = compact.split(/\s+/).filter(Boolean);
  const badSet = new Set(list().map(w => String(w).toLowerCase()));

  const allowed = new Set([
    'fuck', 'fucks', 'fucked', 'fucking',
    'shit', 'shits', 'shitted', 'shitting',
    'bitch', 'bitches', 'bitching',
    'ass', 'asses', 'asshole',
    'damn', 'damned', 'damning',
    'crap', 'craps', 'crappy',
    'arse',
    'bloody',
    'hell'
  ]);

  for (const w of words) {
    if (badSet.has(w)) {
      if (allowed.has(w)) continue;
      return true;
    }
  }
  return false;
};
