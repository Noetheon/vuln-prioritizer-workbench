# The Docker workflow builds these targets and runs the resulting local images.
# Keep registry references here so Dependabot can propose scanner updates.
FROM docker.io/anchore/syft:v1.57.2@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a AS syft

FROM docker.io/anchore/grype:v0.119.0@sha256:8c2c9234a345577a6d321a4753aa3ee1276d8975c8452d2344a56b57733ecad3 AS grype
