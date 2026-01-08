#!/usr/bin/env python3
"""
WSTG Checklist JSON Generator

Fetches OWASP Web Security Testing Guide v4.2 content from official repository
and generates a complete checklist.json with full content.

Usage:
    python3 scripts/generate_wstg_checklist.py

Output:
    src/main/resources/wstg/checklist.json
"""

import json
import re
from typing import Dict, List, Optional
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError
from urllib.parse import quote

# HTML tag constants
BLOCKQUOTE_CLOSE = '</blockquote>'
LIST_CLOSE_TEMPLATE = '</{}>'
CODE_BLOCK_CLOSE = '</code></pre>'
ORDERED_LIST_PATTERN = r'^\d+\.\s'

# HTML entity constants
HTML_AMP = '&amp;'
HTML_LT = '&lt;'
HTML_GT = '&gt;'

# OWASP WSTG v4.2 base URL
BASE_URL = "https://raw.githubusercontent.com/OWASP/www-project-web-security-testing-guide/master/v42/4-Web_Application_Security_Testing"

# Category mapping (order matters for proper sequencing)
CATEGORIES = {
    "01-Information_Gathering": {
        "name": "Information Gathering",
        "id": "WSTG-INFO"
    },
    "02-Configuration_and_Deployment_Management_Testing": {
        "name": "Configuration and Deployment Management Testing",
        "id": "WSTG-CONF"
    },
    "03-Identity_Management_Testing": {
        "name": "Identity Management Testing",
        "id": "WSTG-IDNT"
    },
    "04-Authentication_Testing": {
        "name": "Authentication Testing",
        "id": "WSTG-ATHN"
    },
    "05-Authorization_Testing": {
        "name": "Authorization Testing",
        "id": "WSTG-ATHZ"
    },
    "06-Session_Management_Testing": {
        "name": "Session Management Testing",
        "id": "WSTG-SESS"
    },
    "07-Input_Validation_Testing": {
        "name": "Input Validation Testing",
        "id": "WSTG-INPV"
    },
    "08-Testing_for_Error_Handling": {
        "name": "Testing for Error Handling",
        "id": "WSTG-ERRH"
    },
    "09-Testing_for_Weak_Cryptography": {
        "name": "Testing for Weak Cryptography",
        "id": "WSTG-CRYP"
    },
    "10-Business_Logic_Testing": {
        "name": "Business Logic Testing",
        "id": "WSTG-BUSL"
    },
    "11-Client-side_Testing": {
        "name": "Client-side Testing",
        "id": "WSTG-CLNT"
    },
    "12-API_Testing": {
        "name": "API Testing",
        "id": "WSTG-APIT"
    }
}


def fetch_url(url: str) -> Optional[str]:
    """Fetch content from URL with error handling."""
    try:
        with urlopen(url, timeout=10) as response:
            return response.read().decode('utf-8')
    except URLError as e:
        print(f"Error fetching {url}: {e}")
        return None


def parse_markdown_sections(markdown: str) -> Dict[str, str]:
    """
    Parse markdown into sections based on ## headers.
    Returns dict with section names as keys and HTML content as values.
    """
    sections = {}
    current_section = None
    current_content = []
    
    lines = markdown.split('\n')
    
    for line in lines:
        # Check for ## header (h2)
        if line.startswith('## '):
            # Save previous section
            if current_section:
                sections[current_section.lower()] = markdown_to_html('\n'.join(current_content))
            
            # Start new section
            current_section = line[3:].strip()
            current_content = []
        elif current_section:
            current_content.append(line)
    
    # Save last section
    if current_section:
        sections[current_section.lower()] = markdown_to_html('\n'.join(current_content))
    
    return sections




class MarkdownParser:
    """Parser for converting markdown to HTML with state management."""
    
    def __init__(self):
        self.html = []
        self.in_list = False
        self.list_type = None
        self.in_code_block = False
        self.in_blockquote = False
    
    def parse(self, markdown: str) -> str:
        """Parse markdown and return HTML."""
        if not markdown.strip():
            return ""
        
        lines = markdown.split('\n')
        i = 0
        
        while i < len(lines):
            i = self._process_line(lines, i)
        
        self._close_all_open_elements()
        return '\n'.join(self.html)
    
    def _process_line(self, lines: List[str], index: int) -> int:
        """Process a single line and return next index."""
        line = lines[index]
        stripped = line.strip()
        
        # Delegate to appropriate handler based on line type
        if self.in_code_block:
            self._handle_code_block_content(line, stripped)
        elif stripped.startswith('```'):
            self._start_code_block()
        elif self._is_horizontal_rule(stripped):
            self._handle_horizontal_rule()
        elif stripped.startswith('> '):
            self._handle_blockquote(stripped)
        elif self.in_blockquote and stripped and not stripped.startswith('>'):
            self._close_blockquote()
        elif self._is_unordered_list(stripped):
            self._handle_unordered_list(stripped)
        elif self._is_ordered_list(stripped):
            self._handle_ordered_list(stripped)
        elif self._should_close_list(stripped):
            self._close_list()
            self._handle_content_line(stripped)
        elif self._is_heading(stripped):
            self._handle_heading(stripped)
        elif not stripped:
            self._handle_empty_line()
        else:
            self._handle_paragraph(stripped)
        
        return index + 1
    
    def _handle_code_block_content(self, line: str, stripped: str):
        """Handle content inside code block."""
        if stripped.startswith('```'):
            self.html.append(CODE_BLOCK_CLOSE)
            self.in_code_block = False
        else:
            escaped = line.replace('&', HTML_AMP).replace('<', HTML_LT).replace('>', HTML_GT)
            self.html.append(escaped)
    
    def _start_code_block(self):
        """Start a new code block."""
        self._close_list()
        self._close_blockquote()
        self.html.append('<pre><code>')
        self.in_code_block = True
    
    def _is_horizontal_rule(self, stripped: str) -> bool:
        """Check if line is a horizontal rule."""
        return stripped in ['---', '***', '___'] or bool(re.match(r'^-{3,}$|^\*{3,}$|^_{3,}$', stripped))
    
    def _handle_horizontal_rule(self):
        """Handle horizontal rule."""
        self._close_list()
        self._close_blockquote()
        self.html.append('<hr>')
    
    def _handle_blockquote(self, stripped: str):
        """Handle blockquote line."""
        self._close_list()
        if not self.in_blockquote:
            self.html.append('<blockquote>')
            self.in_blockquote = True
        content = stripped[2:]
        self.html.append(f'<p>{inline_markdown(content)}</p>')
    
    def _is_unordered_list(self, stripped: str) -> bool:
        """Check if line is unordered list item."""
        return stripped.startswith('- ') or stripped.startswith('* ')
    
    def _is_ordered_list(self, stripped: str) -> bool:
        """Check if line is ordered list item."""
        return bool(re.match(ORDERED_LIST_PATTERN, stripped))
    
    def _handle_unordered_list(self, stripped: str):
        """Handle unordered list item."""
        self._close_blockquote()
        self._ensure_list_open('ul')
        content = stripped[2:].strip()
        self.html.append(f'<li>{inline_markdown(content)}</li>')
    
    def _handle_ordered_list(self, stripped: str):
        """Handle ordered list item."""
        self._close_blockquote()
        self._ensure_list_open('ol')
        content = re.sub(ORDERED_LIST_PATTERN, '', stripped)
        self.html.append(f'<li>{inline_markdown(content)}</li>')
    
    def _ensure_list_open(self, list_type: str):
        """Ensure correct list type is open."""
        if not self.in_list or self.list_type != list_type:
            if self.in_list:
                self.html.append(LIST_CLOSE_TEMPLATE.format(self.list_type))
            self.html.append(f'<{list_type}>')
            self.in_list = True
            self.list_type = list_type
    
    def _should_close_list(self, stripped: str) -> bool:
        """Check if we should close the current list."""
        return (self.in_list and stripped and 
                not stripped.startswith(('-', '*')) and 
                not self._is_ordered_list(stripped))
    
    def _is_heading(self, stripped: str) -> bool:
        """Check if line is a heading."""
        return bool(re.match(r'^#{1,6}\s+.+$', stripped))
    
    def _handle_heading(self, stripped: str):
        """Handle heading."""
        self._close_blockquote()
        heading_match = re.match(r'^(#{1,6})\s+(.+)$', stripped)
        if heading_match:
            level = len(heading_match.group(1))
            content = heading_match.group(2)
            self.html.append(f'<h{level}>{inline_markdown(content)}</h{level}>')
    
    def _handle_empty_line(self):
        """Handle empty line."""
        self._close_blockquote()
        if not self.in_list:
            self.html.append('<br>')
    
    def _handle_paragraph(self, stripped: str):
        """Handle paragraph."""
        self._close_blockquote()
        self.html.append(f'<p>{inline_markdown(stripped)}</p>')
    
    def _handle_content_line(self, stripped: str):
        """Handle content line after closing list."""
        if self._is_heading(stripped):
            self._handle_heading(stripped)
        elif stripped:
            self._handle_paragraph(stripped)
    
    def _close_list(self):
        """Close list if open."""
        if self.in_list:
            self.html.append(LIST_CLOSE_TEMPLATE.format(self.list_type))
            self.in_list = False
            self.list_type = None
    
    def _close_blockquote(self):
        """Close blockquote if open."""
        if self.in_blockquote:
            self.html.append(BLOCKQUOTE_CLOSE)
            self.in_blockquote = False
    
    def _close_all_open_elements(self):
        """Close any remaining open elements."""
        self._close_list()
        self._close_blockquote()
        if self.in_code_block:
            self.html.append(CODE_BLOCK_CLOSE)


def markdown_to_html(markdown: str) -> str:
    """
    Convert markdown to simple HTML for Swing rendering.
    Handles: headings, paragraphs, lists, links, code blocks, blockquotes, 
    horizontal rules, bold, italic, strikethrough.
    """
    parser = MarkdownParser()
    return parser.parse(markdown)


def inline_markdown(text: str) -> str:
    """Convert inline markdown (links, bold, italic, strikethrough, code)."""
    # Inline code first (to avoid processing markdown inside code)
    text = re.sub(r'`([^`]+)`', _escape_code, text)
    
    # Links: [text](url) - using a helper to encode URLs
    def _handle_link(match):
        text = match.group(1)
        url = match.group(2)
        # Encode URL but preserve common characters
        encoded_url = quote(url, safe=':/?#[]@!$&\'()*+,;=')
        return f'<a href="{encoded_url}">{text}</a>'
        
    text = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', _handle_link, text)
    
    # Bold: **text** or __text__ (do ** first to avoid conflict with *)
    text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'__([^_]+)__', r'<strong>\1</strong>', text)
    
    # Strikethrough: ~~text~~
    text = re.sub(r'~~([^~]+)~~', r'<del>\1</del>', text)
    
    # Italic: *text* or _text_ (after bold to avoid conflict)
    text = re.sub(r'\*([^*]+)\*', r'<em>\1</em>', text)
    text = re.sub(r'\b_([^_]+)_\b', r'<em>\1</em>', text)
    
    return text


def _escape_code(match) -> str:
    """Escape HTML entities inside code."""
    code = match.group(1)
    code = code.replace('&', HTML_AMP).replace('<', HTML_LT).replace('>', HTML_GT)
    return f'<code>{code}</code>'


def extract_test_id_from_filename(filename: str) -> Optional[str]:
    """Extract WSTG test ID from filename (e.g., '01-Test_Name.md' -> 'WSTG-XXXX-01')."""
    match = re.match(r'(\d+)-', filename)
    if match:
        return match.group(1)
    return None


def _collect_sub_tests_map(readme_content: str) -> Dict[str, List[Dict]]:
    """Build a map of parent test number to its sub-tests."""
    sub_test_pattern = re.compile(r'^-\s*\d+\.\d+\.(\d+)\.(\d+)\s+\[([^\]]+)\]\((\d+\.\d+-[^)]+\.md)\)', re.MULTILINE)
    sub_tests_map = {}
    
    for match in sub_test_pattern.finditer(readme_content):
        parent_num = match.group(1)
        sub_num = match.group(2)
        test_name = match.group(3)
        test_file = match.group(4)
        
        if parent_num not in sub_tests_map:
            sub_tests_map[parent_num] = []
        
        sub_tests_map[parent_num].append({
            'sub_num': sub_num,
            'name': test_name,
            'file': test_file
        })
    
    return sub_tests_map


def _process_main_tests(readme_content: str, category_path: str, category_info: Dict, sub_tests_map: Dict) -> List[Dict]:
    """Process main tests and their sub-tests."""
    tests = []
    main_test_pattern = re.compile(r'^\d+\.\d+\.(\d+)\s+\[([^\]]+)\]\((\d+-[^)]+\.md)\)', re.MULTILINE)
    
    for match in main_test_pattern.finditer(readme_content):
        test_num = match.group(1)
        test_name = match.group(2)
        test_file = match.group(3)
        
        # Add main test
        test_id = f"{category_info['id']}-{test_num.zfill(2)}"
        test_entry = fetch_single_test(category_path, test_id, test_name, test_file)
        if test_entry:
            tests.append(test_entry)
            print(f"  ✓ {test_id}: {test_name}")
        
        # Add sub-tests for this parent (if any)
        if test_num in sub_tests_map:
            for sub_test in sub_tests_map[test_num]:
                sub_test_id = f"{category_info['id']}-{test_num.zfill(2)}.{sub_test['sub_num']}"
                sub_entry = fetch_single_test(category_path, sub_test_id, sub_test['name'], sub_test['file'])
                if sub_entry:
                    tests.append(sub_entry)
                    print(f"    ✓ {sub_test_id}: {sub_test['name']}")
    
    return tests


def fetch_category_tests(category_path: str, category_info: Dict) -> List[Dict]:
    """Fetch all tests for a given category, including sub-tests in proper order."""
    readme_url = f"{BASE_URL}/{category_path}/README.md"
    
    print(f"Fetching {category_info['name']}...")
    readme_content = fetch_url(readme_url)
    
    if not readme_content:
        print(f"  ⚠️  Failed to fetch README for {category_info['name']}")
        return []
    
    # Build sub-tests mapping
    sub_tests_map = _collect_sub_tests_map(readme_content)
    
    # Process main tests and their sub-tests
    return _process_main_tests(readme_content, category_path, category_info, sub_tests_map)


def fetch_single_test(category_path: str, test_id: str, test_name: str, test_file: str) -> Optional[Dict]:
    """Fetch and parse a single test file."""
    # Fetch test markdown
    test_url = f"{BASE_URL}/{category_path}/{test_file}"
    test_md = fetch_url(test_url)
    
    if not test_md:
        print(f"  ⚠️  Failed to fetch {test_id}: {test_name}")
        return None
    
    # Parse sections
    sections = parse_markdown_sections(test_md)
    
    # Build reference URL (stable version)
    ref_url = f"https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/{category_path}/{test_file.replace('.md', '.html')}"
    
    # Extract objectives from "Test Objectives" section
    objectives = []
    if 'test objectives' in sections:
        obj_html = sections['test objectives']
        # Extract text from <li> tags
        obj_matches = re.findall(r'<li>([^<]+)</li>', obj_html)
        objectives = [obj.strip() for obj in obj_matches]
    
    return {
        "id": test_id,
        "name": test_name,
        "reference": ref_url,
        "objectives": objectives,
        "summary": sections.get('summary', ''),
        "howToTest": sections.get('how to test', ''),
        "references": sections.get('references', '')
    }


def generate_checklist_json() -> Dict:
    """Generate complete checklist JSON."""
    checklist = {
        "version": "4.2",
        "categories": {}
    }
    
    for category_path, category_info in CATEGORIES.items():
        tests = fetch_category_tests(category_path, category_info)
        
        if tests:
            checklist["categories"][category_info["name"]] = {
                "id": category_info["id"],
                "tests": tests
            }
    
    return checklist


def main():
    """Main execution."""
    print("=" * 60)
    print("WSTG Checklist JSON Generator v1.0")
    print("=" * 60)
    print()
    
    # Generate checklist
    checklist = generate_checklist_json()
    
    # Count total tests
    total_tests = sum(len(cat["tests"]) for cat in checklist["categories"].values())
    
    print()
    print("=" * 60)
    print(f"Generated {total_tests} tests across {len(checklist['categories'])} categories")
    print("=" * 60)
    
    # Write to file
    output_path = Path(__file__).parent.parent / "src" / "main" / "resources" / "wstg" / "checklist.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(checklist, f, indent=4, ensure_ascii=False)
    
    print(f"\n✓ Written to: {output_path}")
    print(f"  File size: {output_path.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
