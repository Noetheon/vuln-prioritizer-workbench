const accessTokenKey = "access_token"

export function getAccessToken(): string {
  return localStorage.getItem(accessTokenKey) ?? ""
}

export function isLoggedIn(): boolean {
  return getAccessToken().length > 0
}

export function setAccessToken(token: string): void {
  localStorage.setItem(accessTokenKey, token)
}

export function clearAccessToken(): void {
  localStorage.removeItem(accessTokenKey)
}
