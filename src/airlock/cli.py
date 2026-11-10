"""Command-line entry point."""

import click

from airlock import __version__


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="airlock")
def main() -> None:
    """Prepare, inspect, sign and verify deliveries for transfer across an air gap."""
