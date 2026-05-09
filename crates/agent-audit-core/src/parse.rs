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
