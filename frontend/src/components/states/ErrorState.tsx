import { AlertCircle } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"

type ErrorStateProps = {
  message: string
}

export function ErrorState({ message }: ErrorStateProps) {
  return (
    <Card
      className="border-[var(--vpw-red)] bg-[var(--vpw-bg-critical)]"
      role="alert"
    >
      <CardContent className="flex items-center gap-3 p-4">
        <AlertCircle className="h-5 w-5 shrink-0 text-[var(--vpw-red)]" />
        <p className="text-[var(--vpw-red)] text-sm">{message}</p>
      </CardContent>
    </Card>
  )
}
