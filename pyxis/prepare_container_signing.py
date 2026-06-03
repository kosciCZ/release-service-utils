import argparse
import json
import logging
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from find_signatures import find_signatures_for_repository

LOGGER = logging.getLogger("prepare_container_signing")

PYXIS_INSTANCE_MAP = {
    "production": "https://graphql-pyxis.api.redhat.com/graphql/",
    "production-internal": "https://graphql.pyxis.engineering.redhat.com/graphql/",
    "stage": "https://graphql-pyxis.preprod.api.redhat.com/graphql/",
    "stage-internal": "https://graphql.pyxis.stage.engineering.redhat.com/graphql/",
}


def setup_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare container signing configuration.")
    parser.add_argument(
        "--pyxis-server",
        required=True,
        choices=PYXIS_INSTANCE_MAP.keys(),
        help="Pyxis server instance to use",
    )
    parser.add_argument(
        "--pyxis-server",
        required=True,
        choices=PYXIS_INSTANCE_MAP.keys(),
        help="Pyxis server instance to use",
    )
    parser.add_argument(
        "--snapshot", required=True, type=Path, help="Konflux release snapshot path"
    )
    parser.add_argument("--data-file", required=True, type=Path, help="Konflux data file path")
    parser.add_argument(
        "--sign-registry-access-file",
        required=True,
        type=Path,
        help="File containing repositories that require registry-access signing (one per line)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose output",
    )
    return parser


def setup_logger(level: int = logging.INFO):
    log_format = "%(asctime)s [%(name)s] %(levelname)s %(message)s"
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(level)
    logging.basicConfig(level=level, format=log_format, handlers=[stream_handler])


def get_pyxis_instance(pyxis_server: str) -> str:
    pyxis_url = PYXIS_INSTANCE_MAP.get(pyxis_server)
    if not pyxis_url:
        raise ValueError(
            "Invalid pyxisServer parameter. Only 'production', 'production-internal', "
            "'stage-internal' and 'stage' allowed."
        )
    LOGGER.debug("Resolved pyxis server '%s' to URL: %s", pyxis_server, pyxis_url)
    return pyxis_url


SINGLE_MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}


def get_all_image_digests(image_reference: str) -> list[str]:
    """
    Return all manifest digests for an image. Always includes the top-level
    digest. For multi-arch/index images, also includes nested manifest digests.
    """
    top_level_digest = image_reference.split("@", 1)[1]

    result = subprocess.run(
        [
            "skopeo",
            "inspect",
            "--retry-times",
            "3",
            "--no-tags",
            "--raw",
            f"docker://{image_reference}",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    raw_manifest = json.loads(result.stdout)

    digests = [top_level_digest]

    media_type = raw_manifest.get("mediaType", "")
    if media_type not in SINGLE_MANIFEST_MEDIA_TYPES:
        manifests = raw_manifest.get("manifests")
        if manifests:
            digests.extend(m["digest"] for m in manifests)
        else:
            LOGGER.info("Single-manifest artifact (e.g. Helm chart), no nested digests to add")

    LOGGER.info("Manifest digests: %s", " ".join(digests))
    return digests


def get_source_container_digest(
    component: dict[str, Any], default_push_source_container: bool
) -> str | None:
    """
    Resolve the source container digest for a component, if source container
    signing is enabled. Returns None if source container is not requested.
    """

    if not component.get("pushSourceContainer", default_push_source_container):
        return None

    reference_container_image = component["containerImage"]
    source_repo = reference_container_image.split("@sha256:", 1)[0]
    sha = reference_container_image.split("@sha256:", 1)[1]
    source_reference = f"{source_repo}:sha256-{sha}.src"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as auth_file:
        select_auth = subprocess.run(
            ["select-oci-auth", source_reference],
            capture_output=True,
            text=True,
            check=True,
        )
        auth_file.write(select_auth.stdout)
        auth_file.flush()

        result = subprocess.run(
            ["oras", "resolve", "--registry-config", auth_file.name, source_reference],
            capture_output=True,
            text=True,
            check=True,
        )

    digest = result.stdout.strip()
    LOGGER.info("Source container digest for %s: %s", source_reference, digest)
    return digest


def find_existing_signatures(
    pyxis_url: str,
    digests: list[str],
    repositories: list[str],
    max_workers: int = 10,
) -> dict[tuple[str, str], set[str]]:
    """
    Look up existing signatures in Pyxis for all (digest, repository)
    combinations concurrently. Returns a mapping from (digest, repository)
    to the set of "reference key_id" strings already signed.
    """
    lookups = {(digest, repo) for digest in digests for repo in repositories}

    results: dict[tuple[str, str], set[str]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(find_signatures_for_repository, pyxis_url, repo, digest): (digest, repo)
            for digest, repo in lookups
        }
        for future in as_completed(futures):
            key = futures[future]
            results[key] = future.result()
            LOGGER.info("Found %d existing signatures for %s in %s", len(results[key]), *key)

    return results


def process_component(
    component: dict[str, Any],
    data_file: dict[str, Any],
    sign_registry_access_repos: set[str],
    pyxis_url: str,
    max_workers: int = 10,
) -> dict[tuple[str, str], set[str]]:
    digests = get_all_image_digests(component["containerImage"])
    source_container_digest = get_source_container_digest(
        component,
        data_file.get("mapping", {}).get("defaults", {}).get("pushSourceContainer", True),
    )

    all_digests = [*digests]
    if source_container_digest:
        all_digests.append(source_container_digest)

    repositories = [
        repo["rh-registry-repo"].split("/", 1)[1]
        for repo in component.get("repositories", [])
    ]

    return find_existing_signatures(pyxis_url, all_digests, repositories, max_workers)




def main():  # pragma: no cover
    parser = setup_argparser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logger(level=log_level)

    pyxis_url = PYXIS_INSTANCE_MAP[args.pyxis_server]
    LOGGER.info("Using Pyxis instance URL: %s", pyxis_url)

    sign_registry_access_repos = set(
        args.sign_registry_access_file.read_text().splitlines()
    )

    snapshot = json.load(args.snapshot)
    for component in snapshot.get("components", []):
        process_component(component, args.data_file, sign_registry_access_repos)


if __name__ == "__main__":  # pragma: no cover
    main()
