import unicodedata
import re
import sys
import json
import argparse
import os
from datetime import datetime

# --- Configuration ---

# Set of known invisible or problematic formatting characters to REMOVE
INVISIBLE_CHARS_TO_REMOVE = {
    '\u200B',  # Zero Width Space
    '\u200C',  # Zero Width Non-Joiner
    '\u200D',  # Zero Width Joiner
    '\u2060',  # Word Joiner
    '\u00AD',  # Soft Hyphen
    '\u200E',  # Left-to-Right Mark
    '\u200F',  # Right-to-Left Mark
    '\u202A',  # Left-to-Right Embedding
    '\u202B',  # Right-to-Left Embedding
    '\u202C',  # Pop Directional Formatting
    '\u202D',  # Left-to-Right Override
    '\u202E',  # Right-to-Left Override
    '\u2061',  # Function Application
    '\u2062',  # Invisible Times
    '\u2063',  # Invisible Separator
    '\u2064',  # Invisible Plus
    '\uFEFF',  # Zero Width No-Break Space (BOM) - remove only if not at start
}
# Add category Cf (Format) chars, excluding the ones above and whitespace/controls already handled
# Be cautious with this, might include things needed by some scripts (e.g., Arabic shaping)
# for i in range(sys.maxunicode):
#     char = chr(i)
#     if unicodedata.category(char) == 'Cf' and char not in INVISIBLE_CHARS_TO_REMOVE:
#         INVISIBLE_CHARS_TO_REMOVE.add(char)


# ASCII Control Characters (0x00-0x1F) + DEL (0x7F) to REMOVE
# Except for Tab (0x09), LineFeed (0x0A), Carriage Return (0x0D)
ASCII_CONTROL_CHARS_TO_REMOVE = {
    chr(i) for i in range(0x00, 0x20) if chr(i) not in ('\t', '\n', '\r')
} | {chr(0x7F)}

# Regex to find sequences of 2+ whitespace characters for reporting
EXCESSIVE_WHITESPACE_REGEX = re.compile(r'\s{2,}')
# Regex used in cleaning to normalize ALL whitespace sequences to a single space
WHITESPACE_NORMALIZATION_REGEX = re.compile(r'\s+')

# Standard/Common Whitespace characters (for detection reporting)
STANDARD_WHITESPACE = {' ', '\t', '\n', '\r', '\u00A0'} # Include NBSP as somewhat common

# --- Detection Function ---

def detect_potential_watermarks(original_text: str) -> dict:
    """
    Analyzes text to detect potential signs of hidden watermarks.

    Args:
        original_text: The input string to analyze.

    Returns:
        A dictionary containing detailed findings.
    """
    if not isinstance(original_text, str):
        raise TypeError("Input must be a string")

    findings = {
        "metadata": {}, # Will be added later
        "summary": {
            "invisible_chars": 0,
            "ascii_control_chars": 0,
            "non_standard_whitespace": 0,
            "excessive_whitespace_sequences": 0,
            "normalized_chars": 0, # Potential homoglyphs/compatibility chars changed by NFKC
            "total_anomalies_found": 0,
        },
        "details": {
            "invisible_chars": [],
            "ascii_control_chars": [],
            "non_standard_whitespace": [],
            "excessive_whitespace_sequences": [],
            "normalized_chars": [],
        }
    }

    # 1. Check for specific invisible and control characters
    for i, char in enumerate(original_text):
        codepoint = f"U+{ord(char):04X}"
        anomaly_found = False

        # Check Invisible/Formatting Chars (Exclude BOM at index 0)
        if char in INVISIBLE_CHARS_TO_REMOVE:
            if not (char == '\uFEFF' and i == 0):
                findings["details"]["invisible_chars"].append({
                    "index": i, "char": char, "codepoint": codepoint,
                    "description": "Known invisible/formatting character"
                })
                anomaly_found = True

        # Check ASCII Control Chars (excluding allowed whitespace)
        if char in ASCII_CONTROL_CHARS_TO_REMOVE:
            findings["details"]["ascii_control_chars"].append({
                "index": i, "char": repr(char), "codepoint": codepoint,
                "description": "Disallowed ASCII control character"
            })
            anomaly_found = True

        # Check for non-standard whitespace
        if char.isspace() and char not in STANDARD_WHITESPACE:
            findings["details"]["non_standard_whitespace"].append({
                "index": i, "char": repr(char), "codepoint": codepoint,
                "description": "Non-standard whitespace character"
            })
            anomaly_found = True

        # Check for characters changed by NFKC normalization (potential homoglyphs/compatibility)
        # Exclude chars already flagged and standard whitespace changes
        if not anomaly_found and not char.isspace():
            normalized_char = unicodedata.normalize('NFKC', char)
            if char != normalized_char and normalized_char: # Ensure not empty string result
                 # Avoid flagging legitimate multi-char decompositions like 'ﬁ' -> 'fi' as simple homoglyphs
                 # Check if the normalized form is just standard ASCII/common chars
                 is_common_decomposition = len(normalized_char) > 1 and all('a' <= c.lower() <= 'z' or c.isdigit() or c in ' -' for c in normalized_char)

                 if not is_common_decomposition:
                     findings["details"]["normalized_chars"].append({
                         "index": i, "original_char": char, "original_codepoint": codepoint,
                         "normalized_char": normalized_char,
                         "normalized_codepoint": " ".join(f"U+{ord(c):04X}" for c in normalized_char),
                         "description": "Character changed by NFKC normalization (potential homoglyph or compatibility char)"
                     })
                 # Even if common decomposition, we count it as a change
                 # findings["summary"]["normalized_chars"] += 1 # Counted below

    # 2. Check for excessive whitespace sequences
    for match in EXCESSIVE_WHITESPACE_REGEX.finditer(original_text):
        findings["details"]["excessive_whitespace_sequences"].append({
            "start_index": match.start(),
            "end_index": match.end(),
            "sequence": repr(match.group(0)),
            "length": len(match.group(0)),
            "description": "Sequence of multiple whitespace characters"
        })

    # 3. Update Summary Counts
    findings["summary"]["invisible_chars"] = len(findings["details"]["invisible_chars"])
    findings["summary"]["ascii_control_chars"] = len(findings["details"]["ascii_control_chars"])
    findings["summary"]["non_standard_whitespace"] = len(findings["details"]["non_standard_whitespace"])
    findings["summary"]["excessive_whitespace_sequences"] = len(findings["details"]["excessive_whitespace_sequences"])
    findings["summary"]["normalized_chars"] = len(findings["details"]["normalized_chars"])

    findings["summary"]["total_anomalies_found"] = (
        findings["summary"]["invisible_chars"] +
        findings["summary"]["ascii_control_chars"] +
        findings["summary"]["non_standard_whitespace"] +
        findings["summary"]["excessive_whitespace_sequences"] +
        findings["summary"]["normalized_chars"]
    )

    return findings

# --- Cleaning Function ---

def clean_text_from_watermarks(text: str) -> str:
    """
    Cleans text by normalizing Unicode, removing known invisible/control characters,
    and standardizing whitespace to mitigate potential hidden watermarks.

    Args:
        text: The input string to clean.

    Returns:
        The cleaned string.
    """
    if not isinstance(text, str):
        raise TypeError("Input must be a string")
    if not text:
        return ""

    cleaned_text = text

    # 1. Handle BOM (U+FEFF) specifically: remove if not at the very beginning
    if len(cleaned_text) > 0 and cleaned_text[0] == '\uFEFF':
        bom = cleaned_text[0]
        cleaned_text = cleaned_text[1:]
        has_initial_bom = True
    else:
        bom = ""
        has_initial_bom = False

    # 2. Unicode Normalization (NFKC)
    cleaned_text = unicodedata.normalize('NFKC', cleaned_text)

    # 3. Remove specific invisible and formatting characters (post-normalization)
    # Note: Some might have been normalized away already
    cleaned_text = "".join(c for c in cleaned_text if c not in INVISIBLE_CHARS_TO_REMOVE)

    # 4. Remove specific ASCII control characters (except \t, \n, \r)
    cleaned_text = "".join(c for c in cleaned_text if c not in ASCII_CONTROL_CHARS_TO_REMOVE)

    # 5. Normalize Whitespace
    # Replace any sequence of whitespace chars with a single standard space.
    cleaned_text = WHITESPACE_NORMALIZATION_REGEX.sub(' ', cleaned_text)

    # 6. Trim leading/trailing whitespace (including the substituted space)
    cleaned_text = cleaned_text.strip()

    # 7. Re-add initial BOM if it was present and cleaning didn't make text empty
    if has_initial_bom and cleaned_text:
        cleaned_text = bom + cleaned_text
    elif has_initial_bom and not cleaned_text:
         # If cleaning removed everything, don't add BOM back to empty string
         pass

    return cleaned_text

# --- Report Generation Functions ---

def generate_human_report(findings: dict, input_filename: str) -> str:
    """Generates a human-readable Markdown report from the findings."""
    report_lines = [
        f"# Watermark Analysis Report for: `{os.path.basename(input_filename)}`",
        f"Analysis Timestamp: {findings['metadata']['timestamp']}",
        f"Original File Size: {findings['metadata']['original_size']} bytes",
        f"Total Anomalies Detected: {findings['summary']['total_anomalies_found']}",
        "\n## Summary of Findings",
        f"- **Known Invisible/Formatting Characters:** {findings['summary']['invisible_chars']}",
        f"- **Disallowed ASCII Control Characters:** {findings['summary']['ascii_control_chars']}",
        f"- **Non-Standard Whitespace Characters:** {findings['summary']['non_standard_whitespace']}",
        f"- **Excessive Whitespace Sequences (>=2):** {findings['summary']['excessive_whitespace_sequences']}",
        f"- **Characters Changed by NFKC Normalization:** {findings['summary']['normalized_chars']}",
        "\n## Detailed Findings"
    ]

    if not findings['summary']['total_anomalies_found']:
        report_lines.append("\n*No potential watermarking anomalies detected.*")
    else:
        for category, details in findings["details"].items():
            if details:
                report_lines.append(f"\n### {category.replace('_', ' ').title()}")
                report_lines.append("| Index | Character | CodePoint | Details |")
                report_lines.append("|---|---|---|---|")
                for item in details:
                    char_repr = item.get('char', item.get('original_char', item.get('sequence', 'N/A')))
                    # Escape pipe characters in representation for Markdown table
                    char_display = repr(char_repr).replace('|', '\\|')
                    codepoint = item.get('codepoint', item.get('original_codepoint', 'N/A'))
                    desc = item.get('description', '')
                    if 'normalized_char' in item:
                        desc += f" (Normalized to: {repr(item['normalized_char'])} {item['normalized_codepoint']})"
                    if 'length' in item:
                        desc += f" (Length: {item['length']})"

                    report_lines.append(f"| {item.get('index', item.get('start_index', 'N/A'))} | `{char_display}` | {codepoint} | {desc} |")

    return "\n".join(report_lines)

def generate_json_report(findings: dict, input_filename: str, output_path: str):
    """Generates a JSON report file from the findings."""
    # Add metadata to the findings structure before dumping
    findings["metadata"]["input_filename"] = os.path.basename(input_filename)
    # Timestamp and size already added in main()

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(findings, f, ensure_ascii=False, indent=4)
        print(f"Successfully generated JSON report: {output_path}")
    except IOError as e:
        print(f"Error writing JSON report to {output_path}: {e}", file=sys.stderr)
    except TypeError as e:
        print(f"Error serializing findings to JSON: {e}", file=sys.stderr)


# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(
        description="Detects and removes potential hidden text watermarks from a file. "
                    "Generates a cleaned text file, a human-readable Markdown report, "
                    "and a machine-readable JSON report."
    )
    parser.add_argument("input_file", help="Path to the input text file (UTF-8 encoded).")
    parser.add_argument(
        "-o", "--output-basename",
        help="Basename for output files. If not provided, uses the input filename without extension. "
             "Outputs will be <basename>_cleaned.txt, <basename>_report.md, <basename>_report.json"
    )
    # Add verbosity later if needed with logging module

    args = parser.parse_args()

    input_path = args.input_file
    if not os.path.isfile(input_path):
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    # Determine output base name
    if args.output_basename:
        base_name = args.output_basename
    else:
        base_name = os.path.splitext(os.path.basename(input_path))[0]

    output_dir = os.path.dirname(input_path) # Output in the same directory as input by default
    cleaned_path = os.path.join(output_dir, f"{base_name}_cleaned.txt")
    report_md_path = os.path.join(output_dir, f"{base_name}_report.md")
    report_json_path = os.path.join(output_dir, f"{base_name}_report.json")

    # Read the input file
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            original_text = f.read()
        original_size = os.path.getsize(input_path)
        print(f"Successfully read input file: {input_path} ({original_size} bytes)")
    except Exception as e:
        print(f"Error reading input file {input_path}: {e}", file=sys.stderr)
        sys.exit(1)

    # --- Analysis ---
    print("Analyzing text for potential watermarks...")
    analysis_findings = detect_potential_watermarks(original_text)

    # Add metadata needed for reports
    analysis_findings["metadata"]["timestamp"] = datetime.now().isoformat()
    analysis_findings["metadata"]["original_size"] = original_size

    # --- Cleaning ---
    print("Cleaning text...")
    cleaned_text = clean_text_from_watermarks(original_text)

    # --- Output Generation ---

    # 1. Write Cleaned Text File
    try:
        with open(cleaned_path, 'w', encoding='utf-8') as f:
            f.write(cleaned_text)
        print(f"Successfully generated cleaned text file: {cleaned_path}")
    except IOError as e:
        print(f"Error writing cleaned file to {cleaned_path}: {e}", file=sys.stderr)

    # 2. Generate and Write Human-Readable Report (Markdown)
    try:
        markdown_report = generate_human_report(analysis_findings, input_path)
        with open(report_md_path, 'w', encoding='utf-8') as f:
            f.write(markdown_report)
        print(f"Successfully generated Markdown report: {report_md_path}")
    except IOError as e:
        print(f"Error writing Markdown report to {report_md_path}: {e}", file=sys.stderr)

    # 3. Generate and Write JSON Report
    generate_json_report(analysis_findings, input_path, report_json_path)

    print("\nProcessing complete.")
    if analysis_findings["summary"]["total_anomalies_found"] > 0:
        print(f"Detected {analysis_findings['summary']['total_anomalies_found']} potential anomalies. Check reports for details.")
    else:
        print("No potential watermarking anomalies detected.")


if __name__ == "__main__":
    main()