//! Executive HTML report.

use crate::error::{ProductError, Result};
use crate::redaction::{escape_html, redact_product_text};
use crate::report::{agentic_report_section, document_shell, finalize_html, vm_title};
use crate::view_model::{GateResult, ProductViewModel};

pub fn render_executive_html(vm: &ProductViewModel) -> Result<String> {
    let banner = vm.summary.classification.banner_text();
    let title = vm_title(vm, "Executive Report");
    let gate = format!("{:?}", vm.summary.gate);
    let agentic = agentic_report_section(vm, false).map_err(ProductError::internal)?;
    let limitations = vm
        .summary
        .limitations
        .iter()
        .map(|l| format!("<li>{}</li>", escape_html(&redact_product_text(l))))
        .collect::<Vec<_>>()
        .join("\n");
    let top = vm
        .summary
        .top_finding_ids
        .iter()
        .map(|id| {
            let finding = vm.findings.iter().find(|f| f.id == *id);
            let title = finding.map(|f| f.title.as_str()).unwrap_or(id.as_str());
            format!(
                "<li><code>{}</code> — {}</li>",
                escape_html(&redact_product_text(id)),
                escape_html(&redact_product_text(title))
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let gate_note = match vm.summary.gate {
        GateResult::Pass => "Assessment gate passed.",
        GateResult::Fail => "Assessment gate failed — remediation required.",
        GateResult::Partial => "Assessment completed with partial coverage.",
        GateResult::Blocked => "Assessment blocked by policy or environment.",
        GateResult::Inconclusive => "Assessment inconclusive — review evidence.",
    };

    let body = format!(
        r#"<header>
<h1>{title}</h1>
<p class="meta">Run <code>{run}</code> · Profile <code>{profile}</code> · Generated {when}</p>
</header>
<section>
<h2>Scope</h2>
<p>Project <strong>{project}</strong> assessed with profile <code>{profile}</code>
({profile_ver}). Privacy mode: <code>{privacy}</code>. Offline: <code>{offline}</code>.</p>
</section>
<section>
<h2>Assessment Coverage</h2>
<p>Overall coverage: <strong>{overall:.0}%</strong>. Required coverage: <strong>{required:.0}%</strong>.</p>
</section>
{agentic}
<section>
<h2>Gate Result</h2>
<p><strong>{gate}</strong> — {gate_note}</p>
</section>
<section>
<h2>Severity Distribution</h2>
<table>
<tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr>
<tr><td>{c}</td><td>{h}</td><td>{m}</td><td>{l}</td><td>{i}</td></tr>
</table>
</section>
<section>
<h2>Top Findings</h2>
<ul>
{top}
</ul>
</section>
<section>
<h2>Attack-Path Summary</h2>
<p>{paths}</p>
</section>
<section>
<h2>Validation Status</h2>
<p>{validation}</p>
</section>
<section>
<h2>Limitations</h2>
<ul>
{limitations}
</ul>
</section>
"#,
        title = escape_html(&redact_product_text(&title)),
        run = escape_html(&vm.summary.run_id),
        profile = escape_html(&vm.summary.profile),
        profile_ver = escape_html(&vm.summary.profile_version),
        when = escape_html(&vm.summary.generated_at),
        project = escape_html(&redact_product_text(&vm.summary.project_name)),
        privacy = escape_html(&vm.summary.privacy_mode),
        offline = vm.summary.offline,
        overall = vm.summary.overall_coverage * 100.0,
        required = vm.summary.required_coverage * 100.0,
        agentic = agentic,
        gate = escape_html(&gate),
        gate_note = gate_note,
        c = vm.summary.severity_counts.critical,
        h = vm.summary.severity_counts.high,
        m = vm.summary.severity_counts.medium,
        l = vm.summary.severity_counts.low,
        i = vm.summary.severity_counts.info,
        top = if top.is_empty() {
            "<li>None</li>".to_owned()
        } else {
            top
        },
        paths = escape_html(&redact_product_text(&vm.summary.attack_path_summary)),
        validation = escape_html(&redact_product_text(&vm.summary.validation_status)),
        limitations = if limitations.is_empty() {
            "<li>None documented</li>".to_owned()
        } else {
            limitations
        },
    );

    let html = document_shell(&title, &banner, &body);
    finalize_html("executive.html", html).map_err(ProductError::internal)
}
