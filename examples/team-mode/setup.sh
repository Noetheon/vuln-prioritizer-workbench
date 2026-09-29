#!/usr/bin/env bash
# Prepare the team-mode example: create random Authelia secrets on the first run
# and add a user to authelia/users_database.yml.
#
#   ./setup.sh <username> <email> ["Display Name"] [group ...]
#
# Users join the "workbench" group unless other groups are given; only that
# group may open the Workbench. The password comes from VPW_EXAMPLE_PASSWORD or
# an interactive prompt. Restart Authelia after adding users to a running setup.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

fail() {
  echo "$1" >&2
  exit 2
}

[[ $# -ge 2 ]] || fail 'Usage: ./setup.sh <username> <email> ["Display Name"] [group ...]'
username="$1"
email="$2"
display_name="${3:-$1}"
shift $(($# < 3 ? $# : 3))
if [[ $# -gt 0 ]]; then
  groups=("$@")
else
  groups=(workbench)
fi

name_pattern='^[a-z][a-z0-9._-]*$'
[[ "$username" =~ $name_pattern ]] ||
  fail "Usernames start with a lowercase letter and may contain digits, '.', '_' and '-'."
[[ "$email" =~ ^[^@[:space:]\"]+@[^@[:space:]\"]+$ ]] || fail "The email address is not valid."
[[ "$display_name" != *[\"\\]* ]] || fail "The display name must not contain quotes or backslashes."
for group in "${groups[@]}"; do
  [[ "$group" =~ $name_pattern ]] ||
    fail "Group names start with a lowercase letter and may contain digits, '.', '_' and '-'."
done

users_file=authelia/users_database.yml
if [[ -f "$users_file" ]] && grep -q "^  \"$username\":$" "$users_file"; then
  fail "User '$username' already exists in $users_file."
fi

password="${VPW_EXAMPLE_PASSWORD:-}"
if [[ -z "$password" ]]; then
  read -rsp "Password for $username: " password
  echo
  read -rsp "Repeat the password: " repeated
  echo
  [[ "$password" == "$repeated" ]] || fail "The passwords do not match."
fi
[[ ${#password} -ge 12 ]] || fail "Use a password with at least 12 characters."

umask 077
mkdir -p secrets
for secret in session_secret storage_encryption_key; do
  [[ -s "secrets/$secret" ]] || openssl rand -hex 32 >"secrets/$secret"
done

# Authelia hashes the password itself (argon2id). The password is visible in
# the local process list for the second the container runs.
authelia_image="$(sed -n 's/^[[:space:]]*image:[[:space:]]*\(authelia\/authelia:[^[:space:]]*\).*/\1/p' compose.yml)"
[[ -n "$authelia_image" ]] || fail "compose.yml does not name an Authelia image."
digest="$(docker run --rm "$authelia_image" authelia crypto hash generate argon2 --password "$password" |
  sed -n 's/^Digest: //p')"
[[ "$digest" == \$argon2id\$* ]] || fail "Could not hash the password with $authelia_image."

[[ -f "$users_file" ]] || printf 'users:\n' >"$users_file"
{
  printf '  "%s":\n' "$username"
  printf '    displayname: "%s"\n' "$display_name"
  printf '    email: "%s"\n' "$email"
  printf "    password: '%s'\n" "$digest"
  printf '    groups:\n'
  printf '      - "%s"\n' "${groups[@]}"
} >>"$users_file"

echo "Added $username <$email> in group(s) ${groups[*]} to $users_file."
