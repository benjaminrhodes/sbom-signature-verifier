import sys
import click
from pathlib import Path
from src.parsers.spdx import SPDXParser
from src.parsers.cyclonedx import CycloneDXParser
from src.verifier import IntegrityVerifier


@click.group()
def cli():
    """SBOM Signature Verifier - Verify SBOM integrity and signatures."""
    pass


@cli.command()
@click.argument("sbom_file", type=click.Path(exists=True))
def parse(sbom_file):
    """Parse and display SBOM contents."""
    content = Path(sbom_file).read_text()

    if content.strip().startswith("{"):
        parser = CycloneDXParser()
    else:
        parser = SPDXParser()

    sbom = parser.parse(content)
    click.echo(f"Format: {sbom.format.value}")
    click.echo(f"Version: {sbom.version}")
    click.echo(f"Packages: {len(sbom.packages)}")
    for pkg in sbom.packages:
        click.echo(f"  - {pkg.name}@{pkg.version or 'N/A'}")
    return 0


@cli.command()
@click.argument("sbom_file", type=click.Path(exists=True))
@click.option(
    "--key", type=click.Path(exists=True), help="Public key file for signature verification"
)
@click.option(
    "--directory", type=click.Path(), default=".", help="Base directory for file verification"
)
def verify(sbom_file, key, directory):
    """Verify SBOM integrity and signatures."""
    content = Path(sbom_file).read_text()

    if content.strip().startswith("{"):
        parser = CycloneDXParser()
    else:
        parser = SPDXParser()

    sbom = parser.parse(content)
    base_path = Path(directory)

    verifier = IntegrityVerifier()
    results = verifier.verify_sbom(sbom, base_path)

    for result in results:
        if result.verified:
            click.echo(f"[PASS] {result.message}")
        else:
            click.echo(f"[FAIL] {result.message}")
            if result.expected_hash:
                click.echo(f"  Expected: {result.expected_hash}")
                click.echo(f"  Actual: {result.actual_hash}")

    if key and sbom.packages:
        click.echo("Signature verification requires detached signature file")

    return 0


if __name__ == "__main__":
    sys.exit(cli())
