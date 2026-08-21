//! HTML report renderers (executive + technical).

mod executive;
mod technical;

pub use executive::render_executive_html;
pub use technical::render_technical_html;

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
