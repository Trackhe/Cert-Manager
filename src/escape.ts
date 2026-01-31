/**
 * Escaping für HTML und JSON in Script-Tags (XSS / Parser-Brüche vermeiden).
 */
export function htmlEscape(value: string): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function attrEscape(value: string): string {
  return String(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
}

export function escapeForScript(value: string): string {
  return value.replace(/<\/script\s*>/gi, '<\\/script>');
}
