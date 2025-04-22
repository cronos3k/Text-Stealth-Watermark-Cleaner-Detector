      
# Text Stealth Watermark Cleaner & Detector

A Python script designed to detect and meticulously remove potential hidden watermarks embedded in text, often utilizing invisible Unicode characters, whitespace patterns, or homoglyphs. This tool aims to restore text privacy and ensure the output truly reflects user intent, free from tracking mechanisms.

## The Problem: Hidden Watermarks in AI-Generated Text

As Large Language Models (LLMs) become more integrated into creative and productive workflows, concerns arise about methods used to track or identify AI-generated content. One subtle technique involves embedding "watermarks" directly into the text output. These are often **invisible to the human eye** but detectable by algorithms. Methods include:

*   **Invisible Unicode Characters:** Zero-width spaces, joiners, non-joiners, soft hyphens, etc.
*   **Whitespace Manipulation:** Using specific patterns of single/double spaces, non-standard spaces (thin space, em space), or trailing whitespace.
*   **Homoglyphs:** Replacing standard ASCII characters with visually identical characters from other Unicode blocks (e.g., Greek 'Α' for Latin 'A').
*   **Control Characters:** Inserting non-printing ASCII control characters.

These watermarks can persist even when text is copied and pasted, potentially allowing generated content to be traced back or identified in ways the user did not intend.

## Why This Tool is Valuable (The Moral Argument)

Artificial Intelligence, particularly LLMs, should be viewed as powerful **tools** that augment human intellect, creativity, and productivity. When a user collaborates with an AI, the resulting work is a product of that partnership, guided by the user's prompts, refinements, and goals.

Embedding hidden, persistent watermarks into this output raises significant ethical concerns:

1.  **Undermines User Ownership:** It subtly implies that the AI's contribution requires tracking or ownership, devaluing the user's intellectual input and direction in the collaborative process. The final output, curated and accepted by the user, should be considered theirs.
2.  **Violates Privacy & Agency:** Users may not be aware they are generating text with hidden identifiers. This lack of transparency violates user agency and potentially enables unforeseen tracking or analysis of how generated text is used.
3.  **Chilling Effect:** The knowledge (or suspicion) that output might be tracked can discourage open exploration and use of AI tools for sensitive or personal brainstorming, drafting, or expression.
4.  **Potential for Misuse:** While proponents might cite safety or attribution, the potential for misuse in surveillance, profiling, or misattributing ideas (if the watermark links unrelated texts) is considerable.

This tool promotes **"Text Freedom"** by providing users with a means to analyze and sanitize text, ensuring the content they use and share is clean and respects their intent and privacy. It empowers users to treat AI output as a true extension of their own toolkit, without hidden strings attached.

## Features

*   **Detects Multiple Watermarking Techniques:** Identifies invisible Unicode characters, ASCII control codes, non-standard whitespace, excessive whitespace sequences, and potential homoglyphs/compatibility characters via Unicode normalization (NFKC).
*   **Effective Cleaning:** Removes identified anomalies and standardizes whitespace while preserving legitimate text content (including accents, symbols, and different scripts).
*   **Unicode Normalization:** Uses NFKC normalization to standardize character representation and handle many visual ambiguities.
*   **Intelligent BOM Handling:** Preserves the UTF-8 Byte Order Mark (BOM) only if present at the very beginning of the file.
*   **Detailed Reporting:**
    *   Generates a human-readable **Markdown report** (`_report.md`) summarizing findings with counts and specific details (character, codepoint, index).
    *   Generates a machine-readable **JSON report** (`_report.json`) containing structured data ideal for automated analysis or building datasets for AI watermark detection models.
*   **Cleaned Text Output:** Produces a separate (`_cleaned.txt`) file containing the sanitized text.
*   **Easy to Use:** Simple command-line interface.
*   **No External Dependencies:** Uses only standard Python libraries.

## Installation

1.  **Requires Python 3.x.** (Tested with Python 3.7+)
2.  No external libraries are needed.
3.  Download the `watermark_cleaner.py` script (or whatever you named it) to your local machine.

## Usage

Run the script from your terminal or command prompt.

**Basic Usage:**

```bash
python watermark_cleaner.py <input_file.txt>

     <input_file.txt>: Path to the text file you want to analyze and clean (must be UTF-8 encoded).

This will generate three files in the same directory as the input file:

    <input_file>_cleaned.txt: The cleaned text.

    <input_file>_report.md: The human-readable analysis report.

    <input_file>_report.json: The machine-readable analysis report.

Specifying Output Names:

Use the -o or --output-basename option to control the naming of the output files.

      
python watermark_cleaner.py <input_file.txt> -o <your_base_name>

    



This will generate:

    <your_base_name>_cleaned.txt

    <your_base_name>_report.md

    <your_base_name>_report.json

Example:

      
# Analyze 'my_document.txt' and create 'my_document_cleaned.txt', etc.
python watermark_cleaner.py my_document.txt

# Analyze 'draft.txt' and create 'cleaned_draft.txt', 'cleaned_draft_report.md', etc.
python watermark_cleaner.py draft.txt -o cleaned_draft

    

Understanding the Output

    _cleaned.txt: This file contains the text after applying normalization and removing/replacing identified anomalies. It should be visually very similar or identical to the original (if no watermarks were present) but free from the hidden elements.

    _report.md: Open this file with a Markdown viewer (or plain text editor). It provides a summary count of detected issues and lists each specific anomaly found, including its type, the character involved, its Unicode codepoint, and its position (index) in the original text.

    _report.json: This file contains structured data useful for programmatic analysis. It mirrors the information in the Markdown report but in JSON format, suitable for ingestion into databases, scripts, or for creating datasets to train AI models that detect watermarking techniques.

Contributing

Contributions are welcome! Please feel free to submit bug reports, feature requests, or pull requests via the GitHub repository Issues and Pull Requests sections.
License

This project is licensed under the terms of the MIT License.

      
MIT License

Copyright (c) 2025 Gregor Koch MaxStudios.de

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

    
