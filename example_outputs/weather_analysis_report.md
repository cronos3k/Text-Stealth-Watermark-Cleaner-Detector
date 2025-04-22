# Watermark Analysis Report for: `weather_watermarked.txt`
Analysis Timestamp: 2025-04-22T08:59:18.921761
Original File Size: 2807 bytes
Total Anomalies Detected: 19

## Summary of Findings
- **Known Invisible/Formatting Characters:** 10
- **Disallowed ASCII Control Characters:** 0
- **Non-Standard Whitespace Characters:** 1
- **Excessive Whitespace Sequences (>=2):** 6
- **Characters Changed by NFKC Normalization:** 2

## Detailed Findings

### Invisible Chars
| Index | Character | CodePoint | Details |
|---|---|---|---|
| 60 | `'\u2060'` | U+2060 | Known invisible/formatting character |
| 71 | `'\u2060'` | U+2060 | Known invisible/formatting character |
| 115 | `'\xad'` | U+00AD | Known invisible/formatting character |
| 178 | `'\u2060'` | U+2060 | Known invisible/formatting character |
| 1622 | `'\xad'` | U+00AD | Known invisible/formatting character |
| 1998 | `'\u2060'` | U+2060 | Known invisible/formatting character |
| 2213 | `'\u2060'` | U+2060 | Known invisible/formatting character |
| 2272 | `'\xad'` | U+00AD | Known invisible/formatting character |
| 2378 | `'\xad'` | U+00AD | Known invisible/formatting character |
| 2710 | `'\u2060'` | U+2060 | Known invisible/formatting character |

### Non Standard Whitespace
| Index | Character | CodePoint | Details |
|---|---|---|---|
| 1202 | `"'\\u2009'"` | U+2009 | Non-standard whitespace character |

### Excessive Whitespace Sequences
| Index | Character | CodePoint | Details |
|---|---|---|---|
| 452 | `"'\\n\\n'"` | N/A | Sequence of multiple whitespace characters (Length: 2) |
| 531 | `"'  '"` | N/A | Sequence of multiple whitespace characters (Length: 2) |
| 909 | `"'\\n\\n'"` | N/A | Sequence of multiple whitespace characters (Length: 2) |
| 1328 | `"' \\n\\n'"` | N/A | Sequence of multiple whitespace characters (Length: 3) |
| 1690 | `"'\\n\\n'"` | N/A | Sequence of multiple whitespace characters (Length: 2) |
| 2211 | `"'\\n\\n'"` | N/A | Sequence of multiple whitespace characters (Length: 2) |

### Normalized Chars
| Index | Character | CodePoint | Details |
|---|---|---|---|
| 92 | `'𝑡'` | U+1D461 | Character changed by NFKC normalization (potential homoglyph or compatibility char) (Normalized to: 't' U+0074) |
| 2409 | `'‑'` | U+2011 | Character changed by NFKC normalization (potential homoglyph or compatibility char) (Normalized to: '‐' U+2010) |