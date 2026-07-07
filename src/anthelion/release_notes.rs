use napi::bindgen_prelude::*;
use napi_derive::napi;
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
use winget_types::locale::ReleaseNotes;

use super::token::resolve_github_token;
use crate::{
    github::{client::GitHub, graphql::types::Html},
    traits::FromHtml,
};

/// Fetch, normalize, and return release notes for a GitHub release tag.
///
/// # Errors
///
/// Returns `GenericFailure` if creating the GitHub client or fetching release data fails.
/// Returns an error from token resolution when no usable token is available.
#[napi]
pub async fn get_formatted_github_release_notes(
    owner: String,
    repo: String,
    tag: String,
    token: Option<String>,
) -> napi::Result<Option<String>> {
    let token = resolve_github_token(token.as_deref())?;

    let github = GitHub::new(&token).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to create GitHub client: {e}"),
        )
    })?;

    let github_values = github
        .get_all_values()
        .owner(owner)
        .repo(repo)
        .tag_name(tag)
        .send()
        .await
        .map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to fetch GitHub release values: {e}"),
            )
        })?;

    Ok(github_values.release_notes.map(|notes| notes.to_string()))
}

#[napi]
/// Convert HTML release notes content to plain text.
///
/// # Errors
///
/// Returns `GenericFailure` if the conversion task panics.
pub async fn html_to_plain_text(html: String) -> napi::Result<Option<String>> {
    tokio::task::spawn_blocking(move || {
        ReleaseNotes::from_html(&Html::new(html)).map(|notes| notes.to_string())
    })
    .await
    .map_err(|e| Error::new(Status::GenericFailure, format!("Task panicked: {e}")))
}

#[napi]
/// Convert Markdown release notes content to plain text.
///
/// # Errors
///
/// Returns `GenericFailure` if the conversion task panics.
pub async fn markdown_to_plain_text(markdown: String) -> napi::Result<Option<String>> {
    tokio::task::spawn_blocking(move || {
        let mut text = String::new();
        let mut seen_heading = false;

        for event in Parser::new_ext(&markdown, Options::all()) {
            match event {
                Event::Start(Tag::Heading { .. }) => {
                    if seen_heading && !text.ends_with("\n\n") {
                        if !text.ends_with('\n') {
                            text.push('\n');
                        }
                        text.push('\n');
                    }
                    seen_heading = true;
                }
                Event::Start(Tag::Item) => {
                    if !text.ends_with('\n') && !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str("- ");
                }
                Event::Text(content)
                | Event::Code(content)
                | Event::Html(content)
                | Event::InlineHtml(content) => text.push_str(&content),
                Event::SoftBreak | Event::HardBreak => text.push('\n'),
                Event::Rule if !text.ends_with('\n') => text.push('\n'),
                Event::TaskListMarker(checked) => {
                    text.push_str(if checked { "[x] " } else { "[ ] " });
                }
                Event::End(tag)
                    if matches!(
                        tag,
                        TagEnd::Paragraph
                            | TagEnd::Heading(..)
                            | TagEnd::BlockQuote(..)
                            | TagEnd::CodeBlock
                            | TagEnd::Item
                            | TagEnd::List(..)
                            | TagEnd::Table
                            | TagEnd::TableHead
                            | TagEnd::TableRow
                    ) && !text.ends_with('\n') =>
                {
                    text.push('\n');
                }
                _ => {}
            }
        }

        let plain_text = text.trim();
        (!plain_text.is_empty()).then(|| plain_text.to_string())
    })
    .await
    .map_err(|e| Error::new(Status::GenericFailure, format!("Task panicked: {e}")))
}
