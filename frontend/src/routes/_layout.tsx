import { createFileRoute, Outlet, redirect } from "@tanstack/react-router"

import { isLoggedIn } from "../auth"

export const Route = createFileRoute("/_layout")({
  beforeLoad: () => {
    if (!isLoggedIn()) {
      throw redirect({ to: "/login" })
    }
  },
  component: () => <Outlet />,
})
