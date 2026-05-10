import { Eye, EyeOff, KeyRound } from "lucide-react"
import { useState } from "react"
import type { ApiTokenCreatePublic } from "@/api-client"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  VpwEmptyState,
  VpwField,
  VpwKeyValueList,
  VpwStatusBanner,
} from "@/components/vpw"
import { formatDateTime, formatScopes } from "./settings-token-model"

type SettingsTokenCreationResultProps = {
  createdApiToken: ApiTokenCreatePublic | null
}

export function SettingsTokenCreationResult({
  createdApiToken,
}: SettingsTokenCreationResultProps) {
  const [revealedTokenId, setRevealedTokenId] = useState<string | null>(null)
  const tokenRevealed = Boolean(
    createdApiToken && revealedTokenId === createdApiToken.id,
  )

  if (!createdApiToken) {
    return (
      <VpwEmptyState
        description="Create a token to receive a one-time cleartext value. Existing tokens are shown below without secrets."
        icon={<KeyRound aria-hidden="true" className="h-5 w-5" />}
        title="No new token created"
      />
    )
  }

  return (
    <section aria-label="Created API token" className="flex flex-col gap-4">
      <VpwStatusBanner
        title={`Token ${createdApiToken.name} created`}
        tone="success"
      >
        Save this one-time token now. It will be cleared when you leave Settings
        and is not listed again.
      </VpwStatusBanner>
      <VpwField
        description="Reveal only long enough to store it in your secret manager."
        htmlFor="created-token-value"
        label="Token"
      >
        <div className="flex flex-col gap-2 sm:flex-row">
          <Input
            className="font-mono sm:flex-1"
            id="created-token-value"
            onFocus={(event) => event.currentTarget.select()}
            readOnly
            type={tokenRevealed ? "text" : "password"}
            value={createdApiToken.token}
          />
          <Button
            aria-pressed={tokenRevealed}
            onClick={() =>
              setRevealedTokenId((currentId) =>
                currentId === createdApiToken.id ? null : createdApiToken.id,
              )
            }
            type="button"
            variant="outline"
          >
            {tokenRevealed ? (
              <EyeOff aria-hidden="true" className="h-4 w-4" />
            ) : (
              <Eye aria-hidden="true" className="h-4 w-4" />
            )}
            {tokenRevealed ? "Hide" : "Reveal"}
          </Button>
        </div>
      </VpwField>
      <VpwKeyValueList
        columns={2}
        items={[
          {
            label: "Scopes",
            value: formatScopes(createdApiToken.scopes),
            tone: "support",
          },
          {
            label: "Created",
            value: formatDateTime(createdApiToken.created_at),
          },
          {
            label: "Expires",
            value: formatDateTime(createdApiToken.expires_at),
          },
        ]}
      />
    </section>
  )
}
