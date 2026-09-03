//! HTML report renderers (executive + technical).

mod executive;
mod technical;

pub use executive::render_executive_html;
pub use technical::render_technical_html;

use crate::agentic_metadata::build_agentic_metadata;
use crate::redaction::{assert_no_secrets, escape_html, redact_product_text};
use crate::view_model::ProductViewModel;

pub(crate) fn document_shell(title: &str, classification_banner: &str, body: &str) -> String {
    let title = escape_html(&redact_product_text(title));
    let banner = escape_html(&redact_product_text(classification_banner));
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{title}</title>
<style>
body {{ font-family: Georgia, "Times New Roman", serif; margin: 2rem; color: #1a1a1a; background: #f7f4ef; }}
header {{ border-bottom: 2px solid #333; padding-bottom: 1rem; margin-bottom: 1.5rem; }}
.banner {{ background: #3d2914; color: #f7f4ef; padding: 0.6rem 0.8rem; font-family: ui-monospace, monospace; font-size: 0.85rem; }}
h1 {{ font-size: 1.8rem; margin: 0.8rem 0 0.2rem; }}
h2 {{ font-size: 1.2rem; margin-top: 1.6rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 0.8rem 0; }}
th, td {{ border: 1px solid #bbb; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }}
th {{ background: #e8e0d5; }}
.meta {{ color: #444; font-size: 0.95rem; }}
code {{ font-family: ui-monospace, monospace; font-size: 0.9em; }}
</style>
</head>
<body>
<div class="banner">{banner}</div>
{body}
</body>
</html>
"#
    )
}

pub(crate) fn agentic_report_section(
    vm: &ProductViewModel,
    detailed: bool,
) -> Result<String, String> {
    let Some(metadata) = build_agentic_metadata(vm).map_err(|e| e.to_string())? else {
        return Ok(String::new());
    };
    let family_rows = metadata
        .get("risk_family_coverage")
        .and_then(serde_json::Value::as_array)
        .map(|families| {
            families
                .iter()
                .map(|family| {
                    let name = family
                        .get("risk_family")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("UNKNOWN");
                    let state = family
                        .get("assessment_state")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("UNASSESSED");
                    let tested = family
                        .get("tested")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    let eligible = family
                        .get("eligible")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    format!(
                        "<tr><td><code>{}</code></td><td>{}</td><td>{}/{}</td></tr>",
                        escape_html(name),
                        escape_html(state),
                        tested,
                        eligible
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();

    let mut html = format!(
        "<section><h2>Agentic Security Coverage</h2><p><strong>Untested or blocked risk families are not treated as secure.</strong></p><table><tr><th>Risk family</th><th>Assessment state</th><th>Tested / eligible</th></tr>{family_rows}</table>"
    );

    if detailed {
        let property_rows = metadata
            .get("properties")
            .and_then(serde_json::Value::as_array)
            .map(|properties| {
                properties
                    .iter()
                    .map(|property| {
                        let id = property
                            .get("property_id")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("UNKNOWN");
                        let family = property
                            .get("risk_family")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("UNKNOWN");
                        let status = property
                            .get("coverage_status")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("NOT_TESTED");
                        let standards = property
                            .get("standards")
                            .map(|value| redact_product_text(&value.to_string()))
                            .unwrap_or_default();
                        format!(
                            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                            escape_html(id),
                            escape_html(family),
                            escape_html(status),
                            escape_html(&standards)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        html.push_str(&format!(
            "<h2>Agentic Property Metadata</h2><table><tr><th>Property</th><th>Risk family</th><th>Coverage status</th><th>Standards</th></tr>{property_rows}</table>"
        ));
    }

    html.push_str("</section>");
    Ok(html)
}

pub(crate) fn finalize_html(label: &str, html: String) -> Result<String, String> {
    assert_no_secrets(label, &html)?;
    if html.contains("<script") || html.contains("javascript:") {
        return Err(format!("{label}: unexpected script content in HTML"));
    }
    Ok(html)
}

pub(crate) fn vm_title(vm: &ProductViewModel, kind: &str) -> String {
    format!("DARE Agent Security — {kind} — {}", vm.summary.project_name)
}
