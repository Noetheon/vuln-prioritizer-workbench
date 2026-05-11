import { ApiError, UsersService } from "../api-client"
import {
  hasReadableSessionEvidence,
  isLoggedIn,
  markAuthenticatedSession,
} from "../auth"

export async function hasAuthenticatedSession(): Promise<boolean> {
  if (isLoggedIn()) {
    return true
  }
  if (!hasReadableSessionEvidence()) {
    return false
  }
  try {
    await UsersService.readUserMe()
  } catch (caught) {
    if (caught instanceof ApiError && caught.status === 401) {
      return false
    }
    return false
  }
  markAuthenticatedSession()
  return true
}
