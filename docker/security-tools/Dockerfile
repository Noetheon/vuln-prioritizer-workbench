# The Docker workflow builds these targets and runs the resulting local images.
# Keep registry references here so Dependabot can propose scanner updates.
FROM docker.io/anchore/syft:v1.55.0@sha256:4cc92b64ca74ffca4c94d4c8fcc01f217731375300be14d0b6eeb2e82eaa110a AS syft

FROM docker.io/anchore/grype:v0.119.0@sha256:8c2c9234a345577a6d321a4753aa3ee1276d8975c8452d2344a56b57733ecad3 AS grype
