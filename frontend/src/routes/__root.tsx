import { createRootRoute, Outlet } from "@/lib/router"

export const Route = createRootRoute({
  component: () => <Outlet />,
})
