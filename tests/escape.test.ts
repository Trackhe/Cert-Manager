import { describe, test, expect } from 'bun:test';
import { htmlEscape, attrEscape, escapeForScript } from '../src/escape.js';

describe('htmlEscape', () => {
  test('escapet &, <, >, "', () => {
    expect(htmlEscape('a & b')).toBe('a &amp; b');
    expect(htmlEscape('<script>')).toBe('&lt;script&gt;');
    expect(htmlEscape('"quoted"')).toBe('&quot;quoted&quot;');
  });

  test('leerer String und Sonderzeichen', () => {
    expect(htmlEscape('')).toBe('');
    expect(htmlEscape('<>')).toBe('&lt;&gt;');
  });
});

describe('attrEscape', () => {
  test('escapet & und " für Attributwerte', () => {
    expect(attrEscape('foo "bar"')).toBe('foo &quot;bar&quot;');
    expect(attrEscape('a & b')).toBe('a &amp; b');
  });
});

describe('escapeForScript', () => {
  test('verhindert schließendes script-Tag', () => {
    expect(escapeForScript('</script>')).toBe('<\\/script>');
    expect(escapeForScript('</SCRIPT>')).toBe('<\\/script>');
    expect(escapeForScript('x</script  >y')).toBe('x<\\/script>y');
  });
});
