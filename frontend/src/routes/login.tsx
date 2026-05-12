import { createFileRoute, redirect } from "@/lib/router"

export const Route = createFileRoute("/login")({
  beforeLoad: () => {
    throw redirect({ search: {} as never, to: "/" })
  },
})
