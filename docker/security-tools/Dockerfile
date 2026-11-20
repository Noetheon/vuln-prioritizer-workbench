# The Docker workflow builds these targets and runs the resulting local images.
# Keep registry references here so Dependabot can propose scanner updates.
FROM docker.io/anchore/syft:v1.52.0@sha256:500e2d872ac019436926e8322b4fc1f39441d94d21f6f4046c6ff29b30e8cb02 AS syft

FROM docker.io/anchore/grype:v0.122.0@sha256:013e16ae96bd64108973e3e9fecec63f7ff276358d34c46c25d33e2aac96539f AS grype
