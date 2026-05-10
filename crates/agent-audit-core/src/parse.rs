// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::Path;

use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Parser, Tag, TagEnd};

use crate::error::{AuditError, AuditResult};
use crate::model::{MarkdownCodeBlock, SkillManifest, SkillReference};

const UTF8_BOM: &str = "\u{feff}";

pub fn parse_skill_manifest(path: &Path, content: &str) -> AuditResult<SkillManifest> {
    let split = split_frontmatter(path, content)?;
    let frontmatter = split.frontmatter;
    let body = split.body;
    let parsed_markdown = parse_markdown_body(body, split.body_start_line);

    let name = frontmatter_string(&frontmatter, "name").or(parsed_markdown.first_h1_heading);
    let description = frontmatter_string(&frontmatter, "description").or_else(|| {
        let paragraph = parsed_markdown.first_paragraph.trim();
        (!paragraph.is_empty()).then(|| paragraph.to_owned())
    });

    Ok(SkillManifest {
        name,
        description,
        frontmatter: frontmatter.clone(),
        body: body.to_owned(),
        headings: parsed_markdown.headings,
        links: parsed_markdown.links,
        inline_code: parsed_markdown.inline_code,
        code_blocks: parsed_markdown.code_blocks,
        declared_tools: frontmatter_string_list(&frontmatter, "tools"),
        declared_permissions: frontmatter_string_list(&frontmatter, "permissions"),
    })
}

struct ParsedMarkdown {
    headings: Vec<String>,
    links: Vec<SkillReference>,
    inline_code: Vec<String>,
    code_blocks: Vec<MarkdownCodeBlock>,
    first_h1_heading: Option<String>,
    first_paragraph: String,
}

struct MarkdownParseState {
    line_index: LineIndex,
    parsed: ParsedMarkdown,
    current_heading: Option<(HeadingLevel, String)>,
    current_code_block: Option<MarkdownCodeBlock>,
    in_first_paragraph: bool,
    captured_first_paragraph: bool,
}

impl MarkdownParseState {
    fn new(body: &str, body_start_line: usize) -> Self {
        Self {
            line_index: LineIndex::new(body, body_start_line),
            parsed: ParsedMarkdown {
                headings: Vec::new(),
                links: Vec::new(),
                inline_code: Vec::new(),
                code_blocks: Vec::new(),
                first_h1_heading: None,
                first_paragraph: String::new(),
            },
            current_heading: None,
            current_code_block: None,
            in_first_paragraph: false,
            captured_first_paragraph: false,
        }
    }

    fn into_parsed(self) -> ParsedMarkdown {
        self.parsed
    }

    fn start_heading(&mut self, level: HeadingLevel) {
        self.current_heading = Some((level, String::new()));
    }

    fn end_heading(&mut self, end_level: HeadingLevel) {
        let Some((start_level, heading)) = self.current_heading.take() else {
            return;
        };

        let heading = heading.trim();
        if heading.is_empty() {
            return;
        }

        if start_level == HeadingLevel::H1
            && end_level == HeadingLevel::H1
            && self.parsed.first_h1_heading.is_none()
        {
            self.parsed.first_h1_heading = Some(heading.to_owned());
        }
        self.parsed.headings.push(heading.to_owned());
    }

    fn start_paragraph(&mut self) {
        if !self.captured_first_paragraph {
            self.in_first_paragraph = true;
        }
    }

    fn end_paragraph(&mut self) {
        if self.in_first_paragraph {
            self.in_first_paragraph = false;
            self.captured_first_paragraph = !self.parsed.first_paragraph.trim().is_empty();
        }
    }

    fn add_reference(&mut self, target: impl Into<String>, offset: usize) {
        self.parsed.links.push(SkillReference {
            target: target.into(),
            line: Some(self.line_index.line_for_offset(offset)),
            exists: None,
        });
    }

    fn start_code_block(&mut self, kind: CodeBlockKind<'_>, offset: usize) {
        self.current_code_block = Some(MarkdownCodeBlock {
            language: code_block_language(kind),
            content: String::new(),
            line: Some(self.line_index.line_for_offset(offset)),
        });
    }

    fn end_code_block(&mut self) {
        if let Some(block) = self.current_code_block.take() {
            self.parsed.code_blocks.push(block);
        }
    }

    fn add_text(&mut self, text: &str) {
        if let Some((_, heading)) = self.current_heading.as_mut() {
            heading.push_str(text);
        }
        if let Some(block) = self.current_code_block.as_mut() {
            block.content.push_str(text);
        }
        if self.in_first_paragraph {
            self.parsed.first_paragraph.push_str(text);
        }
    }

    fn add_inline_code(&mut self, code: impl Into<String>) {
        self.parsed.inline_code.push(code.into());
    }
}

fn parse_markdown_body(body: &str, body_start_line: usize) -> ParsedMarkdown {
    let mut state = MarkdownParseState::new(body, body_start_line);

    for (event, range) in Parser::new(body).into_offset_iter() {
        match event {
            Event::Start(Tag::Heading { level, .. }) => state.start_heading(level),
            Event::End(TagEnd::Heading(level)) => state.end_heading(level),
            Event::Start(Tag::Paragraph) => state.start_paragraph(),
            Event::End(TagEnd::Paragraph) => state.end_paragraph(),
            Event::Start(Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. }) => {
                state.add_reference(dest_url.to_string(), range.start);
            }
            Event::Start(Tag::CodeBlock(kind)) => state.start_code_block(kind, range.start),
            Event::End(TagEnd::CodeBlock) => state.end_code_block(),
            Event::Text(text) => state.add_text(&text),
            Event::Code(code) => state.add_inline_code(code.to_string()),
            _ => {}
        }
    }

    state.into_parsed()
}

fn code_block_language(kind: CodeBlockKind<'_>) -> Option<String> {
    match kind {
        CodeBlockKind::Fenced(language) if !language.is_empty() => Some(language.to_string()),
        _ => None,
    }
}

struct FrontmatterSplit<'a> {
    frontmatter: BTreeMap<String, serde_yaml::Value>,
    body: &'a str,
    body_start_line: usize,
}

enum FrontmatterSlices<'a> {
    Absent,
    Present { frontmatter: &'a str, body: &'a str },
    Unclosed { line: usize },
}

fn split_frontmatter<'a>(path: &Path, content: &'a str) -> AuditResult<FrontmatterSplit<'a>> {
    let (frontmatter, body) = match frontmatter_slices(content) {
        FrontmatterSlices::Absent => {
            return Ok(FrontmatterSplit {
                frontmatter: BTreeMap::new(),
                body: content,
                body_start_line: 1,
            });
        }
        FrontmatterSlices::Present { frontmatter, body } => (frontmatter, body),
        FrontmatterSlices::Unclosed { line } => {
            return Err(AuditError::FrontmatterDelimiter {
                path: path.to_path_buf(),
                line,
                message: "unclosed frontmatter block".to_owned(),
            });
        }
    };

    let parsed = serde_yaml::from_str(frontmatter).map_err(|source| AuditError::Frontmatter {
        path: path.to_path_buf(),
        source,
    })?;

    let body_start_offset = content.len() - body.len();
    Ok(FrontmatterSplit {
        frontmatter: parsed,
        body,
        body_start_line: line_for_content_offset(content, body_start_offset),
    })
}

fn frontmatter_slices(content: &str) -> FrontmatterSlices<'_> {
    let content_after_bom = content.strip_prefix(UTF8_BOM).unwrap_or(content);
    let delimiter_offset = content.len() - content_after_bom.len();
    let Some(after_opening_delimiter) = content_after_bom.strip_prefix("---") else {
        return FrontmatterSlices::Absent;
    };
    let Some(opening_line_ending_len) = line_ending_len(after_opening_delimiter) else {
        return FrontmatterSlices::Absent;
    };
    let frontmatter_start = delimiter_offset + "---".len() + opening_line_ending_len;
    let mut line_start = frontmatter_start;

    while line_start <= content.len() {
        let line_end = content[line_start..]
            .find('\n')
            .map_or(content.len(), |offset| line_start + offset + 1);
        let line = &content[line_start..line_end];
        if trim_line_ending(line) == "---" {
            return FrontmatterSlices::Present {
                frontmatter: &content[frontmatter_start..line_start],
                body: &content[line_end..],
            };
        }
        if line_end == content.len() {
            break;
        }
        line_start = line_end;
    }

    FrontmatterSlices::Unclosed { line: 1 }
}

fn line_ending_len(value: &str) -> Option<usize> {
    if value.starts_with("\r\n") {
        Some(2)
    } else if value.starts_with('\n') {
        Some(1)
    } else {
        None
    }
}

fn trim_line_ending(line: &str) -> &str {
    line.strip_suffix("\r\n")
        .or_else(|| line.strip_suffix('\n'))
        .unwrap_or(line)
}

struct LineIndex {
    body_start_line: usize,
    line_starts: Vec<usize>,
}

impl LineIndex {
    fn new(body: &str, body_start_line: usize) -> Self {
        let mut line_starts = vec![0];
        line_starts.extend(
            body.bytes()
                .enumerate()
                .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
        );

        Self {
            body_start_line,
            line_starts,
        }
    }

    fn line_for_offset(&self, offset: usize) -> usize {
        let line_index = self
            .line_starts
            .partition_point(|line_start| *line_start <= offset)
            .saturating_sub(1);
        self.body_start_line + line_index
    }
}

fn line_for_content_offset(content: &str, offset: usize) -> usize {
    content
        .as_bytes()
        .iter()
        .take(offset)
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

fn frontmatter_string(
    frontmatter: &BTreeMap<String, serde_yaml::Value>,
    key: &str,
) -> Option<String> {
    frontmatter
        .get(key)
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn frontmatter_string_list(
    frontmatter: &BTreeMap<String, serde_yaml::Value>,
    key: &str,
) -> Vec<String> {
    match frontmatter.get(key) {
        Some(serde_yaml::Value::Sequence(values)) => values
            .iter()
            .filter_map(serde_yaml::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        Some(serde_yaml::Value::String(value)) if !value.trim().is_empty() => {
            vec![value.trim().to_owned()]
        }
        _ => Vec::new(),
    }
}

#[allow(dead_code)]
fn heading_rank(level: HeadingLevel) -> u8 {
    match level {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        HeadingLevel::H3 => 3,
        HeadingLevel::H4 => 4,
        HeadingLevel::H5 => 5,
        HeadingLevel::H6 => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn extracts_name_and_description_from_frontmatter() {
        let content = r#"---
name: frontmatter-name
description: Frontmatter description.
---

# Heading Fallback Not Used

Paragraph fallback not used.
"#;

        let manifest = parse(content);

        assert_eq!(manifest.name.as_deref(), Some("frontmatter-name"));
        assert_eq!(
            manifest.description.as_deref(),
            Some("Frontmatter description.")
        );
        assert_eq!(
            manifest.frontmatter.keys().cloned().collect::<Vec<_>>(),
            vec!["description", "name"]
        );
        assert_eq!(
            manifest.body,
            "\n# Heading Fallback Not Used\n\nParagraph fallback not used.\n"
        );
    }

    #[test]
    fn extracts_frontmatter_with_utf8_bom_and_crlf_delimiters() {
        let content = "\u{feff}---\r\nname: windows-authored\r\ndescription: Windows authored fixture.\r\n---\r\n\r\n# Windows Authored\r\n\r\nRead [guide](references/guide.md).\r\n";

        let manifest = parse(content);

        assert_eq!(manifest.name.as_deref(), Some("windows-authored"));
        assert_eq!(
            manifest.description.as_deref(),
            Some("Windows authored fixture.")
        );
        assert_eq!(
            manifest.body,
            "\r\n# Windows Authored\r\n\r\nRead [guide](references/guide.md).\r\n"
        );
        assert_eq!(manifest.links[0].line, Some(8));
    }

    #[test]
    fn extracts_frontmatter_with_mixed_closing_delimiter_line_endings() {
        for (label, content) in [
            (
                "bom lf opening lf closing",
                "\u{feff}---\nname: bom-lf\ndescription: Mixed close.\n---\n# Mixed\n",
            ),
            (
                "lf opening crlf closing",
                "---\nname: mixed-crlf-close\ndescription: Mixed close.\n---\r\n# Mixed\r\n",
            ),
            (
                "crlf opening lf closing",
                "---\r\nname: mixed-lf-close\r\ndescription: Mixed close.\r\n---\n# Mixed\n",
            ),
        ] {
            let manifest = parse(content);

            assert_eq!(
                manifest.description.as_deref(),
                Some("Mixed close."),
                "{label}"
            );
            assert_eq!(manifest.headings, vec!["Mixed"], "{label}");
            assert!(manifest.code_blocks.is_empty(), "{label}");
        }
    }

    #[test]
    fn accepts_frontmatter_closing_delimiter_at_eof_without_trailing_newline() {
        for (label, content) in [
            (
                "lf",
                "---\nname: eof-frontmatter\ndescription: EOF close.\n---",
            ),
            (
                "bom crlf",
                "\u{feff}---\r\nname: eof-frontmatter\r\ndescription: EOF close.\r\n---",
            ),
        ] {
            let manifest = parse(content);

            assert_eq!(manifest.name.as_deref(), Some("eof-frontmatter"), "{label}");
            assert_eq!(
                manifest.description.as_deref(),
                Some("EOF close."),
                "{label}"
            );
            assert_eq!(manifest.body, "", "{label}");
        }
    }

    #[test]
    fn falls_back_to_heading_and_first_paragraph_without_frontmatter() {
        let content = r#"# Fallback Name

Fallback description paragraph.

Second paragraph.
"#;

        let manifest = parse(content);

        assert_eq!(manifest.name.as_deref(), Some("Fallback Name"));
        assert_eq!(
            manifest.description.as_deref(),
            Some("Fallback description paragraph.")
        );
        assert!(manifest.frontmatter.is_empty());
    }

    #[test]
    fn extracts_headings_from_multiple_heading_levels_in_document_order() {
        let content = r#"# Primary

## Secondary

### Tertiary

###### Deep
"#;

        let manifest = parse(content);

        assert_eq!(
            manifest.headings,
            vec!["Primary", "Secondary", "Tertiary", "Deep"]
        );
        assert_eq!(manifest.name.as_deref(), Some("Primary"));
    }

    #[test]
    fn name_fallback_uses_first_top_level_heading_only() {
        let content = r#"## Secondary Is Not A Name

Opening description.

# Primary Name

### Tertiary
"#;

        let manifest = parse(content);

        assert_eq!(
            manifest.headings,
            vec!["Secondary Is Not A Name", "Primary Name", "Tertiary"]
        );
        assert_eq!(manifest.name.as_deref(), Some("Primary Name"));
        assert_eq!(
            manifest.description.as_deref(),
            Some("Opening description.")
        );
    }

    #[test]
    fn name_fallback_ignores_documents_without_top_level_heading() {
        let content = r#"## Secondary Only

Opening description.
"#;

        let manifest = parse(content);

        assert_eq!(manifest.headings, vec!["Secondary Only"]);
        assert!(manifest.name.is_none());
        assert_eq!(
            manifest.description.as_deref(),
            Some("Opening description.")
        );
    }

    #[test]
    fn extracts_markdown_links_without_filtering_targets() {
        let content = r#"---
name: link-fixture
description: Link fixture.
---

# Links

Use [relative](references/guide.md), [absolute](https://example.test/guide),
[mail](mailto:security@example.test), and [anchor](#links).
"#;

        let manifest = parse(content);

        assert_eq!(
            link_targets(&manifest),
            vec![
                "references/guide.md",
                "https://example.test/guide",
                "mailto:security@example.test",
                "#links",
            ]
        );
        assert_eq!(
            manifest
                .links
                .iter()
                .map(|reference| (reference.target.as_str(), reference.line, reference.exists))
                .collect::<Vec<_>>(),
            vec![
                ("references/guide.md", Some(8), None),
                ("https://example.test/guide", Some(8), None),
                ("mailto:security@example.test", Some(9), None),
                ("#links", Some(9), None),
            ]
        );
    }

    #[test]
    fn extracts_markdown_image_destinations_as_references() {
        let content = r#"---
name: image-fixture
description: Image fixture.
---

# Images

Use ![local badge](assets/badge.png) and ![remote badge](vscode://example/icon).
"#;

        let manifest = parse(content);

        assert_eq!(
            manifest
                .links
                .iter()
                .map(|reference| (reference.target.as_str(), reference.line, reference.exists))
                .collect::<Vec<_>>(),
            vec![
                ("assets/badge.png", Some(8), None),
                ("vscode://example/icon", Some(8), None),
            ]
        );
    }

    #[test]
    fn extracts_inline_code_in_document_order() {
        let content = r#"# Inline Code

Run `first`, inspect `second`, then record `third`.
"#;

        let manifest = parse(content);

        assert_eq!(manifest.inline_code, vec!["first", "second", "third"]);
    }

    #[test]
    fn extracts_fenced_code_blocks_with_language_and_content() {
        let content = r#"---
name: parser-fixture
description: Parser fixture description.
tools:
  - shell
  - git
permissions: read-files
---

# Parser Fixture

Use [local docs](references/docs.md), [remote docs](https://example.test/docs),
and `inline-code`.

```bash
echo parser
```
"#;

        let manifest = parse(content);

        assert_eq!(manifest.name.as_deref(), Some("parser-fixture"));
        assert_eq!(
            manifest.description.as_deref(),
            Some("Parser fixture description.")
        );
        assert_eq!(manifest.headings, vec!["Parser Fixture"]);
        assert_eq!(
            manifest
                .links
                .iter()
                .map(|reference| reference.target.as_str())
                .collect::<Vec<_>>(),
            vec!["references/docs.md", "https://example.test/docs"]
        );
        assert_eq!(manifest.inline_code, vec!["inline-code"]);
        assert_eq!(manifest.code_blocks.len(), 1);
        assert_eq!(manifest.code_blocks[0].language.as_deref(), Some("bash"));
        assert_eq!(manifest.code_blocks[0].content, "echo parser\n");
        assert_eq!(manifest.code_blocks[0].line, Some(15));
        assert_eq!(manifest.declared_tools, vec!["shell", "git"]);
        assert_eq!(manifest.declared_permissions, vec!["read-files"]);
    }

    #[test]
    fn extracts_unlabeled_and_indented_code_blocks_without_language() {
        let content = "# Code Blocks\n\n```\nunlabeled\n```\n\n    indented\n";

        let manifest = parse(content);

        assert_eq!(
            manifest
                .code_blocks
                .iter()
                .map(|block| (
                    block.language.as_deref(),
                    block.content.as_str(),
                    block.line
                ))
                .collect::<Vec<_>>(),
            vec![
                (None, "unlabeled\n", Some(3)),
                (None, "indented\n", Some(7)),
            ]
        );
    }

    #[test]
    fn reports_markdown_lines_relative_to_manifest_not_body_slice() {
        let content = r#"---
name: line-numbers
description: Line number fixture.
---

# Line Numbers

Read [guide](references/guide.md).

```bash
echo line
```
"#;

        let manifest = parse(content);

        assert_eq!(manifest.links[0].line, Some(8));
        assert_eq!(manifest.code_blocks[0].line, Some(10));
    }

    #[test]
    fn returns_frontmatter_error_when_opening_delimiter_is_unclosed() {
        let content = r#"---
name: ignored-without-closing-delimiter

# Body Heading

Read [guide](references/guide.md).
"#;

        let error = parse_skill_manifest(Path::new("SKILL.md"), content)
            .expect_err("unclosed frontmatter should fail");

        assert!(matches!(error, AuditError::FrontmatterDelimiter { .. }));
        assert!(error.to_string().contains("unclosed frontmatter"));
    }

    #[test]
    fn extracts_declared_tools_and_permissions_from_sequences() {
        let content = r#"---
name: sequence-capabilities
description: Sequence capabilities.
tools:
  - shell
  - git
  - ""
permissions:
  - read-files
  - write-files
---

# Sequence Capabilities
"#;

        let manifest = parse(content);

        assert_eq!(manifest.declared_tools, vec!["shell", "git"]);
        assert_eq!(
            manifest.declared_permissions,
            vec!["read-files", "write-files"]
        );
    }

    #[test]
    fn extracts_declared_tools_and_permissions_from_scalar_strings() {
        let content = r#"---
name: scalar-capabilities
description: Scalar capabilities.
tools: shell
permissions: read-files
---

# Scalar Capabilities
"#;

        let manifest = parse(content);

        assert_eq!(manifest.declared_tools, vec!["shell"]);
        assert_eq!(manifest.declared_permissions, vec!["read-files"]);
    }

    #[test]
    fn ignores_non_string_and_empty_declared_capability_values() {
        let content = r#"---
name: ignored-capabilities
description: Ignored capabilities.
tools:
  - shell
  - 42
  - " "
permissions:
  nested: value
---

# Ignored Capabilities
"#;

        let manifest = parse(content);

        assert_eq!(manifest.declared_tools, vec!["shell"]);
        assert!(manifest.declared_permissions.is_empty());
    }

    #[test]
    fn returns_frontmatter_error_when_bom_prefixed_opening_delimiter_is_unclosed() {
        let content =
            "\u{feff}---\r\nname: ignored-without-closing-delimiter\r\n\r\n# Body Heading\r\n";

        let error = parse_skill_manifest(Path::new("SKILL.md"), content)
            .expect_err("unclosed frontmatter should fail");

        assert!(matches!(error, AuditError::FrontmatterDelimiter { .. }));
        assert!(error.to_string().contains("unclosed frontmatter"));
    }

    #[test]
    fn returns_frontmatter_error_when_unclosed_delimiter_reaches_eof_without_newline() {
        let content = r#"---
name: ignored-without-closing-delimiter
"#;

        let error = parse_skill_manifest(Path::new("SKILL.md"), content)
            .expect_err("unclosed frontmatter should fail");

        assert!(matches!(error, AuditError::FrontmatterDelimiter { .. }));
        assert!(error.to_string().contains("unclosed frontmatter"));
    }

    #[test]
    fn returns_frontmatter_error_for_malformed_yaml() {
        let content = r#"---
name: [unterminated
---

# Malformed
"#;

        let error = parse_skill_manifest(Path::new("SKILL.md"), content)
            .expect_err("malformed frontmatter should fail");

        assert!(matches!(error, AuditError::Frontmatter { .. }));
        assert!(error.to_string().contains("failed to parse frontmatter"));
    }

    #[test]
    fn returns_frontmatter_error_for_non_map_yaml_frontmatter() {
        let content = r#"---
- name
- description
---

# Non Map
"#;

        let error = parse_skill_manifest(Path::new("SKILL.md"), content)
            .expect_err("sequence frontmatter should fail");

        assert!(matches!(error, AuditError::Frontmatter { .. }));
        assert!(error.to_string().contains("failed to parse frontmatter"));
    }

    #[test]
    fn maps_heading_levels_to_numeric_ranks() {
        assert_eq!(heading_rank(HeadingLevel::H1), 1);
        assert_eq!(heading_rank(HeadingLevel::H2), 2);
        assert_eq!(heading_rank(HeadingLevel::H3), 3);
        assert_eq!(heading_rank(HeadingLevel::H4), 4);
        assert_eq!(heading_rank(HeadingLevel::H5), 5);
        assert_eq!(heading_rank(HeadingLevel::H6), 6);
    }

    #[test]
    fn parsing_same_manifest_twice_produces_same_output() {
        let content = r#"---
name: deterministic-parser
description: Deterministic parser fixture.
permissions:
  - read-files
tools:
  - shell
---

# Deterministic Parser

Read [guide](references/guide.md) and run `agent-audit`.

```bash
agent-audit scan .
```
"#;

        let first = parse(content);
        let second = parse(content);

        assert_eq!(first.name, second.name);
        assert_eq!(first.description, second.description);
        assert_eq!(
            first.frontmatter.keys().collect::<Vec<_>>(),
            second.frontmatter.keys().collect::<Vec<_>>()
        );
        assert_eq!(first.body, second.body);
        assert_eq!(first.headings, second.headings);
        assert_eq!(link_targets(&first), link_targets(&second));
        assert_eq!(first.inline_code, second.inline_code);
        assert_eq!(code_block_summaries(&first), code_block_summaries(&second));
        assert_eq!(first.declared_tools, second.declared_tools);
        assert_eq!(first.declared_permissions, second.declared_permissions);
    }

    fn parse(content: &str) -> SkillManifest {
        parse_skill_manifest(Path::new("SKILL.md"), content).expect("parse manifest")
    }

    fn link_targets(manifest: &SkillManifest) -> Vec<&str> {
        manifest
            .links
            .iter()
            .map(|reference| reference.target.as_str())
            .collect()
    }

    fn code_block_summaries(manifest: &SkillManifest) -> Vec<(Option<&str>, &str, Option<usize>)> {
        manifest
            .code_blocks
            .iter()
            .map(|block| {
                (
                    block.language.as_deref(),
                    block.content.as_str(),
                    block.line,
                )
            })
            .collect()
    }
}
