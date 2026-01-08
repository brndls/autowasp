# WSTG Checklist JSON Generator

This script generates a complete `checklist.json` file from the official OWASP Web Security Testing Guide v4.2 repository.

## Purpose

The bundled `checklist.json` provides offline access to the full WSTG content, including:
- Test objectives
- Summary sections
- Detailed "How to Test" instructions
- References
- Sub-tests (e.g., SQL Injection variants)

## Usage

```bash
python3 scripts/generate_wstg_checklist.py
```

## Output

- **File**: `src/main/resources/wstg/checklist.json`
- **Size**: ~957 KB
- **Content**: 108 test cases across 12 categories (98 main + 10 sub-tests)

## Markdown to HTML Conversion

The script comprehensively converts WSTG markdown to HTML for proper rendering in Burp Suite's JEditorPane.

### Block Elements
- **Headings**: `#` to `######` → `<h1>` to `<h6>`
- **Paragraphs**: Regular text → `<p>`
- **Code blocks**: ` ``` ` → `<pre><code>` (with HTML entity escaping)
- **Unordered lists**: `- ` or `* ` → `<ul><li>`
- **Ordered lists**: `1. ` → `<ol><li>`
- **Blockquotes**: `> ` → `<blockquote>`
- **Horizontal rules**: `---`, `***`, `___` → `<hr>`

### Inline Elements
- **Bold**: `**text**` or `__text__` → `<strong>`
- **Italic**: `*text*` or `_text_` → `<em>`
- **Strikethrough**: `~~text~~` → `<del>`
- **Inline code**: `` `code` `` → `<code>` (with HTML entity escaping)
- **Links**: `[text](url)` → `<a href="url">`

### Special Handling
- HTML entities (`<`, `>`, `&`) are properly escaped in code blocks and inline code
- List types (ordered/unordered) are tracked separately
- Empty lines preserved in code blocks for formatting
- Proper nesting of block elements (lists, blockquotes, code blocks)

## Dependencies

- Python 3.x (standard library only, no external packages)
- Internet connection (to fetch from GitHub)

## Source

Fetches from official OWASP repository:
```
https://raw.githubusercontent.com/OWASP/www-project-web-security-testing-guide/master/v42/
```

## When to Run

1. **Initial setup**: Generate complete checklist data
2. **WSTG updates**: When OWASP releases new versions (e.g., v5.0)
3. **Content fixes**: If upstream markdown is corrected

## Future: WSTG v5.0

When WSTG v5.0 is released:
1. Update `BASE_URL` in script to point to v5.0
2. Update `CATEGORIES` mapping if structure changes
3. Run script to regenerate `checklist.json`
4. Update `LocalChecklistLoader.getVersion()` to return "5.0"
