//! Technical HTML report.

use crate::error::{ProductError, Result};
use crate::redaction::{escape_html, redact_product_text};
use crate::report::{agentic_report_section, document_shell, finalize_html, vm_title};
use crate::view_model::ProductViewModel;

pub fn render_technical_html(vm: &ProductViewModel) -> Result<String> {
    let banner = vm.summary.classification.banner_text();
    let title = vm_title(vm, "Technical Report");
    let agentic = agentic_report_section(vm, true).map_err(ProductError::internal)?;

    let rows = vm
        .findings
        .iter()
        .map(|f| {
            format!(
                r#"<tr>
<td><code>{id}</code></td>
<td>{title}</td>
<td><code>{property}</code></td>
<td>{severity:?}</td>
<td>{confidence}</td>
<td>{component}</td>
<td>{status}</td>
<td>{evidence}</td>
<td>{paths}</td>
<td>{expected}</td>
<td>{observed}</td>
<td>{remediation}</td>
<td>{retest}</td>
</tr>"#,
                id = escape_html(&redact_product_text(&f.id)),
                title = escape_html(&redact_product_text(&f.title)),
                property = escape_html(&redact_product_text(&f.property)),
                severity = f.severity,
                confidence = escape_html(&redact_product_text(&f.confidence)),
                component = escape_html(&redact_product_text(&f.component)),
                status = escape_html(&redact_product_text(&f.status)),
                evidence = escape_html(&redact_product_text(&f.evidence_refs.join(", "))),
                paths = escape_html(&redact_product_text(&f.attack_path_refs.join(", "))),
                expected = escape_html(&redact_product_text(f.expected.as_deref().unwrap_or("-"))),
                observed = escape_html(&redact_product_text(f.observed.as_deref().unwrap_or("-"))),
                remediation = escape_html(&redact_product_text(
                    f.remediation.as_deref().unwrap_or("-")
                )),
                retest = escape_html(&redact_product_text(
                    f.retest_status.as_deref().unwrap_or("-")
                )),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let body = format!(
        r#"<header>
<h1>{title}</h1>
<p class="meta">Run <code>{run}</code> · Gate <strong>{gate:?}</strong> · {when}</p>
</header>
<section>
<h2>Findings</h2>
<table>
<tr>
<th>ID</th><th>Title</th><th>Property</th><th>Severity</th><th>Confidence</th>
<th>Component</th><th>Status</th><th>Evidence</th><th>Attack path</th>
<th>Expected</th><th>Observed</th><th>Remediation</th><th>Retest</th>
</tr>
{rows}
</table>
</section>
{agentic}
"#,
        title = escape_html(&redact_product_text(&title)),
        run = escape_html(&vm.summary.run_id),
        gate = vm.summary.gate,
        when = escape_html(&vm.summary.generated_at),
        rows = if rows.is_empty() {
            "<tr><td colspan=\"13\">No findings</td></tr>".to_owned()
        } else {
            rows
        },
        agentic = agentic,
    );

    let html = document_shell(&title, &banner, &body);
    finalize_html("technical.html", html).map_err(ProductError::internal)
}
