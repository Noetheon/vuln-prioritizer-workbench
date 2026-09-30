# Repository guidance


## Public publication privacy

- Use a pseudonymous Git author and a GitHub `users.noreply.github.com` address for new commits.
- Use synthetic people, affiliations and paths in examples and tests (for example `/Users/example/`).
- Before publishing, inspect source files, PDFs and their metadata, images, archives, commit/tag metadata, issue/PR text, and release/CI outputs for personal information.
- Keep personal detection patterns outside Git. Do not commit a blacklist containing the private names or addresses it is intended to protect.
- Never paste raw terminal logs with personal directory names into issues or pull requests. Replace those paths before publication.
- Run the local privacy guard before commit/push and before uploading documents or release files. The generic CI check complements this; it does not replace personal-pattern checks or image/PDF review.
- History rewrites require a verified backup and checking server-held PR references and cached commits before making a repository public again.
