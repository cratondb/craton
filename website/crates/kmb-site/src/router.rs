//! Router Configuration
//!
//! Route configuration for the website.

use axum::{routing::get, Router};
use tower::ServiceBuilder;
use tower_http::{
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};

use crate::{handlers, state::AppState};

/// Create the main router with all routes.
pub fn create_router(state: AppState) -> Router {
    // Static file service with cache headers
    // In production, files are served with cache-control that requires revalidation.
    // The ?v= query parameter provides cache busting when files change.
    let static_service = ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("public, max-age=31536000, immutable"),
        ))
        .service(ServeDir::new("public"));

    let router = Router::new()
        .route("/", get(handlers::home::home))
        .route("/architecture", get(handlers::architecture::architecture))
        .route("/faq", get(handlers::faq::faq))
        .route("/healthcare", get(handlers::healthcare::healthcare))
        .route("/blog", get(handlers::blog::blog_index))
        .route("/blog/{slug}", get(handlers::blog::blog_post))
        // Documentation routes (dynamic from markdown)
        .route("/docs", get(handlers::docs::docs_index))
        .route("/docs/{*path}", get(handlers::docs::docs_page))
        // Download routes
        .route("/download", get(handlers::download::download))
        .route("/download/manual", get(handlers::download::download_manual))
        // Search API (returns HTML fragment for Datastar)
        .route("/api/search", get(handlers::search::search))
        // Comparison pages
        .route("/compare/{slug}", get(handlers::compare::compare))
        // Pressurecraft routes (interactive teaching workspace)
        .route("/pressurecraft/fcis-flow", get(handlers::pressurecraft::fcis_flow))
        .route("/pressurecraft/determinism-demo", get(handlers::pressurecraft::determinism_demo))
        .nest_service("/public", static_service)
        // Install script served at canonical URL (public/install.sh lives under /public/
        // but curl | sh convention requires it at the root path)
        .route_service("/install.sh", ServeFile::new("public/install.sh"))
        // Security headers applied to all responses
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::CONTENT_SECURITY_POLICY,
            axum::http::HeaderValue::from_static(
                "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
                 style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data: https://img.shields.io; frame-ancestors 'none'",
            ),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            axum::http::HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::REFERRER_POLICY,
            axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(TraceLayer::new_for_http());

    #[cfg(debug_assertions)]
    let router = router.route("/__livereload", get(crate::dev_tools::livereload_handler));

    router.with_state(state)
}
