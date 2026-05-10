// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::Path;

use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Parser, Tag, TagEnd};

use crate::error::{AuditError, AuditResult};
use crate::model::{MarkdownCodeBlock, SkillManifest, SkillReference};

pub fn parse_skill_manifest(path: &Path, content: &str) -> AuditResult<SkillManifest> {
    let (frontmatter, body) = split_frontmatter(path, content)?;
    let mut headings = Vec::new();
    let mut links = Vec::new();
    let mut inline_code = Vec::new();
    let mut code_blocks = Vec::new();
    let mut current_heading: Option<String> = None;
    let mut current_code_block: Option<MarkdownCodeBlock> = None;
    let mut first_paragraph = String::new();
    let mut in_first_paragraph = false;
    let mut captured_first_paragraph = false;

    for event in Parser::new(body) {
        match event {
            Event::Start(Tag::Heading { .. }) => current_heading = Some(String::new()),
            Event::End(TagEnd::Heading(_)) => {
                if let Some(heading) = current_heading.take() {
                    let heading = heading.trim();
                    if !heading.is_empty() {
                        headings.push(heading.to_owned());
                    }
                }
            }
            Event::Start(Tag::Paragraph) if !captured_first_paragraph => {
                in_first_paragraph = true;
            }
            Event::End(TagEnd::Paragraph) if in_first_paragraph => {
                in_first_paragraph = false;
                captured_first_paragraph = !first_paragraph.trim().is_empty();
            }
            Event::Start(Tag::Link { dest_url, .. }) => {
                links.push(SkillReference {
                    target: dest_url.to_string(),
                    line: None,
                    exists: None,
                });
            }
            Event::Start(Tag::CodeBlock(kind)) => {
                let language = match kind {
                    CodeBlockKind::Fenced(language) if !language.is_empty() => {
                        Some(language.to_string())
                    }
                    _ => None,
                };
                current_code_block = Some(MarkdownCodeBlock {
                    language,
                    content: String::new(),
                    line: None,
                });
            }
            Event::End(TagEnd::CodeBlock) => {
                if let Some(block) = current_code_block.take() {
                    code_blocks.push(block);
                }
            }
            Event::Text(text) => {
                if let Some(heading) = current_heading.as_mut() {
                    heading.push_str(&text);
                }
                if let Some(block) = current_code_block.as_mut() {
                    block.content.push_str(&text);
                }
                if in_first_paragraph {
                    first_paragraph.push_str(&text);
                }
            }
            Event::Code(code) => inline_code.push(code.to_string()),
            _ => {}
        }
    }

    let name = frontmatter_string(&frontmatter, "name").or_else(|| first_h1(&headings));
    let description = frontmatter_string(&frontmatter, "description").or_else(|| {
        let paragraph = first_paragraph.trim();
        (!paragraph.is_empty()).then(|| paragraph.to_owned())
    });

    Ok(SkillManifest {
        name,
        description,
        frontmatter: frontmatter.clone(),
        body: body.to_owned(),
        headings,
        links,
        inline_code,
        code_blocks,
        declared_tools: frontmatter_string_list(&frontmatter, "tools"),
        declared_permissions: frontmatter_string_list(&frontmatter, "permissions"),
    })
}

fn split_frontmatter<'a>(
    path: &Path,
    content: &'a str,
) -> AuditResult<(BTreeMap<String, serde_yaml::Value>, &'a str)> {
    let Some(rest) = content.strip_prefix("---\n") else {
        return Ok((BTreeMap::new(), content));
    };

    let Some((frontmatter, body)) = rest.split_once("\n---\n") else {
        return Ok((BTreeMap::new(), content));
    };

    let parsed = serde_yaml::from_str(frontmatter).map_err(|source| AuditError::Frontmatter {
        path: path.to_path_buf(),
        source,
    })?;

    Ok((parsed, body))
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

fn first_h1(headings: &[String]) -> Option<String> {
    headings.first().map(ToOwned::to_owned)
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
        assert!(manifest
            .links
            .iter()
            .all(|reference| reference.line.is_none() && reference.exists.is_none()));
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
            vec![(None, "unlabeled\n", None), (None, "indented\n", None),]
        );
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
    fn treats_unclosed_frontmatter_delimiter_as_markdown_body() {
        let content = r#"---
name: ignored-without-closing-delimiter

# Body Heading
"#;

        let manifest = parse(content);

        assert!(manifest.frontmatter.is_empty());
        assert_eq!(manifest.name.as_deref(), Some("Body Heading"));
        assert_eq!(
            manifest.description.as_deref(),
            Some("name: ignored-without-closing-delimiter")
        );
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
