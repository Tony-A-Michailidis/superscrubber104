"""Reports: one report model, rendered as Markdown, HTML, JSON, CycloneDX or OSCAL.

``superscrubber104 report`` reads a bundle (the packing side's assessment), the output directory of
``superscrubber104 verify`` (this side's own assessment, analysis and receipt) or of
``superscrubber104 model inspect --out``, or a bare assessment file.
"""

import json

from superscrubber104.core.controls import ControlCatalog
from superscrubber104.core.errors import ConfigError
from superscrubber104.core.serde import to_data
from superscrubber104.report.cyclonedx import render_cyclonedx
from superscrubber104.report.html import render_html
from superscrubber104.report.markdown import render_markdown
from superscrubber104.report.model import Report, Source, build_report, load_source
from superscrubber104.report.oscal import render_oscal

FORMATS = ("md", "html", "json", "cyclonedx", "oscal")

__all__ = ["FORMATS", "Report", "Source", "build_report", "load_source", "render"]


def render(source: Source, fmt: str, catalog: ControlCatalog | None = None) -> str:
    if fmt == "cyclonedx":
        if source.analysis is None:
            raise ConfigError(
                "a CycloneDX SBOM needs the analysis, which this source does not have"
            )
        report = build_report(source, catalog)
        return render_cyclonedx(source.analysis, source.assessment, title=report.title)
    report = build_report(source, catalog)
    if fmt == "md":
        return render_markdown(report)
    if fmt == "html":
        return render_html(report)
    if fmt == "json":
        return json.dumps(to_data(report), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if fmt == "oscal":
        return render_oscal(report)
    raise ConfigError(f"unknown report format {fmt!r}; choose from {', '.join(FORMATS)}")
