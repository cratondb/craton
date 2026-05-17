//! Askama Templates
//!
//! Template structs for rendering HTML pages.

use askama::Template;
use askama_web::WebTemplate;

use crate::{content::TocHeading, search::SearchResult, BUILD_VERSION, LATEST_RELEASE};

/// Home page template.
#[derive(Template, WebTemplate)]
#[template(path = "home.html")]
pub struct HomeTemplate {
    pub title: String,
    pub tagline: String,
    /// Build version for cache busting static assets.
    pub v: &'static str,
    /// Latest published Kimberlite release tag (e.g. "v0.5.0"). Sourced
    /// from `KIMBERLITE_LATEST_RELEASE` at build time; the home page
    /// renders it so the visible "Latest Release" string never drifts.
    pub latest_release: &'static str,
}

impl HomeTemplate {
    pub fn new(title: impl Into<String>, tagline: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            tagline: tagline.into(),
            v: BUILD_VERSION,
            latest_release: LATEST_RELEASE,
        }
    }
}

/// Blog list page template.
#[derive(Template, WebTemplate)]
#[template(path = "blog/index.html")]
pub struct BlogListTemplate {
    pub title: String,
    pub posts: Vec<PostSummary>,
    /// Build version for cache busting static assets.
    pub v: &'static str,
}

impl BlogListTemplate {
    pub fn new(title: impl Into<String>, posts: Vec<PostSummary>) -> Self {
        Self {
            title: title.into(),
            posts,
            v: BUILD_VERSION,
        }
    }
}

/// Summary of a blog post for listing.
pub struct PostSummary {
    pub slug: String,
    pub title: String,
    pub date: String,
    pub excerpt: String,
    pub author_name: Option<String>,
    pub author_avatar: Option<String>,
}

/// Individual blog post template.
#[derive(Template, WebTemplate)]
#[template(path = "blog/post.html")]
pub struct BlogPostTemplate {
    pub title: String,
    pub post_title: String,
    pub date: String,
    pub content_html: String,
    pub author_name: Option<String>,
    pub author_avatar: Option<String>,
    /// Build version for cache busting static assets.
    pub v: &'static str,
}

impl BlogPostTemplate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        title: impl Into<String>,
        post_title: impl Into<String>,
        date: impl Into<String>,
        content_html: impl Into<String>,
        author_name: Option<String>,
        author_avatar: Option<String>,
    ) -> Self {
        Self {
            title: title.into(),
            post_title: post_title.into(),
            date: date.into(),
            content_html: content_html.into(),
            author_name,
            author_avatar,
            v: BUILD_VERSION,
        }
    }
}

/// Architecture deep dive page template.
#[derive(Template, WebTemplate)]
#[template(path = "architecture.html")]
pub struct ArchitectureTemplate {
    pub title: String,
    /// Build version for cache busting static assets.
    pub v: &'static str,
}

impl ArchitectureTemplate {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            v: BUILD_VERSION,
        }
    }
}

/// FAQ page template.
#[derive(Template, WebTemplate)]
#[template(path = "faq.html")]
pub struct FaqTemplate {
    pub title: String,
    /// Build version for cache busting static assets.
    pub v: &'static str,
}

impl FaqTemplate {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            v: BUILD_VERSION,
        }
    }
}

/// Healthcare vertical landing page template.
#[derive(Template, WebTemplate)]
#[template(path = "healthcare.html")]
pub struct HealthcareTemplate {
    pub title: String,
    /// Build version for cache busting static assets.
    pub v: &'static str,
}

impl HealthcareTemplate {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            v: BUILD_VERSION,
        }
    }
}

/// A link in the sidebar navigation.
pub struct SidebarLink {
    pub title: String,
    pub href: String,
    pub is_active: bool,
}

/// A section in the sidebar navigation.
pub struct SidebarSection {
    pub name: String,
    pub key: String,
    pub links: Vec<SidebarLink>,
    pub default_expanded: bool,
}

/// Documentation page template (rendered from markdown).
#[derive(Template, WebTemplate)]
#[template(path = "docs/page.html")]
pub struct DocsPageTemplate {
    pub title: String,
    pub page_title: String,
    pub section_name: String,
    pub active_page: String,
    pub content_html: String,
    pub headings: Vec<TocHeading>,
    pub sidebar_sections: Vec<SidebarSection>,
    /// Build version for cache busting static assets.
    pub v: &'static str,
}

/// Download page template.
#[derive(Template, WebTemplate)]
#[template(path = "download.html")]
pub struct DownloadTemplate {
    pub title: String,
    /// Build version for cache busting static assets.
    pub v: &'static str,
}

impl DownloadTemplate {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            v: BUILD_VERSION,
        }
    }
}

/// Pressurecraft: FCIS Flow diagram page template.
#[derive(Template, WebTemplate)]
#[template(path = "pressurecraft/fcis-flow.html")]
pub struct PressurecraftFcisFlowTemplate {
    pub title: String,
    /// Build version for cache busting static assets.
    pub v: &'static str,
}

impl PressurecraftFcisFlowTemplate {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            v: BUILD_VERSION,
        }
    }
}

/// Pressurecraft: Determinism demo page template.
#[derive(Template, WebTemplate)]
#[template(path = "pressurecraft/determinism-demo.html")]
pub struct PressurecraftDeterminismTemplate {
    pub title: String,
    /// Build version for cache busting static assets.
    pub v: &'static str,
}

impl PressurecraftDeterminismTemplate {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            v: BUILD_VERSION,
        }
    }
}

/// A use case bullet point for comparison pages.
pub struct UseCase {
    pub title: String,
    pub detail: String,
}

/// A row in the feature comparison table.
pub struct ComparisonRow {
    pub feature: String,
    pub competitor_value: String,
    pub kimberlite_value: String,
    pub kimberlite_advantage: bool,
}

/// All data needed to render a comparison page.
pub struct ComparisonData {
    pub competitor: String,
    pub slug: String,
    pub tagline: String,
    pub intro: String,
    pub competitor_best_for: String,
    pub kimberlite_best_for: String,
    pub competitor_use_cases: Vec<UseCase>,
    pub kimberlite_use_cases: Vec<UseCase>,
    pub rows: Vec<ComparisonRow>,
    pub architecture_left_title: String,
    pub architecture_left_description: String,
    pub architecture_right_title: String,
    pub architecture_right_description: String,
}

/// Comparison page template (vs PostgreSQL, TigerBeetle, CockroachDB).
#[derive(Template, WebTemplate)]
#[template(path = "compare.html")]
pub struct CompareTemplate {
    pub title: String,
    pub data: ComparisonData,
    /// Build version for cache busting static assets.
    pub v: &'static str,
}

impl CompareTemplate {
    pub fn new(data: ComparisonData) -> Self {
        let title = format!("Kimberlite vs {}", data.competitor);
        Self {
            title,
            data,
            v: BUILD_VERSION,
        }
    }
}

/// Search results HTML fragment (no base layout — morphed by Datastar).
#[derive(Template)]
#[template(path = "_partials/search_results.html")]
pub struct SearchResultsTemplate {
    pub results: Vec<SearchResult>,
    pub query: String,
}
