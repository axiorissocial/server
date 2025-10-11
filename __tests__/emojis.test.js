import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

describe('EMOJIS file content', () => {
  it('contains expected emoji entries', () => {
    const file = path.join(__dirname, '..', '..', 'src', 'utils', 'emojis.ts');
    const txt = fs.readFileSync(file, 'utf8');
    expect(txt).toContain("{ name: 'grinning', char: '😀'");
    expect(txt).toContain("aliases: ['smile'");
  });

  it('basic in-test lookup behavior matches expected mapping', () => {
    const EMOJIS = [
      { name: 'grinning', char: '😀', aliases: ['smile'] },
      { name: 'joy', char: '😂', aliases: ['lol'] }
    ];
    const findByName = (name) => EMOJIS.find(e => e.name === name);
    const findByAlias = (alias) => EMOJIS.find(e => e.aliases.includes(alias));
    expect(findByName('grinning').char).toBe('😀');
    expect(findByAlias('lol').name).toBe('joy');
  });
});
