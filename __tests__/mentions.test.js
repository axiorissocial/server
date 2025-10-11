import { describe, it, expect } from 'vitest';

const extractMentions = (content) => {
  const mentionRegex = /@(\w+)/g;
  const mentions = [];
  let match;
  while ((match = mentionRegex.exec(content)) !== null) {
    const username = match[1];
    if (!mentions.includes(username)) mentions.push(username);
  }
  return mentions;
};

describe('mentions utilities', () => {
  it('extractMentions returns unique usernames in order', () => {
    const content = 'Hello @alice and @bob, have you seen @alice? @charlie';
    const res = extractMentions(content);
    expect(res).toEqual(['alice', 'bob', 'charlie']);
  });

  it('processMentions returns content unchanged (plaintext behavior)', () => {
    const content = 'Hey @dave, check this out';
    expect(processMentions(content)).toBe(content);
  });

  it('getCursorMentionContext detects mention context correctly', () => {
    const el = { value: 'Hello @al', selectionStart: 9 };
    const ctx = getCursorMentionContext(el);
    expect(ctx.isMention).toBe(true);
    expect(ctx.query).toBe('al');
    expect(ctx.startPos).toBe(6);
  });

  it('insertMention inserts username and sets cursor', () => {
    const ta = {
      value: 'Hello @',
      selectionStart: 7,
      setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; },
      dispatchEvent(evt) { /* noop */ }
    };
    insertMention(ta, 'zoe', 6);
    expect(ta.value).toBe('Hello @zoe ');
    expect(ta.selectionStart).toBe(6 + 'zoe'.length + 2);
  });
});

const processMentions = (content) => content;

const getCursorMentionContext = (element) => {
  const cursorPos = element.selectionStart || 0;
  const textBeforeCursor = element.value.substring(0, cursorPos);
  const lastAtIndex = textBeforeCursor.lastIndexOf('@');
  if (lastAtIndex === -1) return { isMention: false, query: '', startPos: -1 };
  const textAfterAt = textBeforeCursor.substring(lastAtIndex + 1);
  if (/\s/.test(textAfterAt)) return { isMention: false, query: '', startPos: -1 };
  return { isMention: true, query: textAfterAt, startPos: lastAtIndex };
};

const insertMention = (element, username, startPos) => {
  const cursorPos = element.selectionStart || 0;
  const textBefore = element.value.substring(0, startPos);
  const textAfter = element.value.substring(cursorPos);
  const newValue = textBefore + `@${username} ` + textAfter;
  element.value = newValue;
  const newCursorPos = startPos + username.length + 2;
  element.setSelectionRange(newCursorPos, newCursorPos);
  const event = new Event('input', { bubbles: true });
  element.dispatchEvent(event);
};
