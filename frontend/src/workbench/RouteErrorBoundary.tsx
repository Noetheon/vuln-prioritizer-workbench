import { Component, type ErrorInfo, type ReactNode } from "react"
import { ErrorState } from "../components/states"

type RouteErrorBoundaryProps = {
  children: ReactNode
  resetKey: string
}

type RouteErrorBoundaryState = {
  hasError: boolean
}

export class RouteErrorBoundary extends Component<
  RouteErrorBoundaryProps,
  RouteErrorBoundaryState
> {
  state: RouteErrorBoundaryState = { hasError: false }

  static getDerivedStateFromError(): RouteErrorBoundaryState {
    return { hasError: true }
  }

  componentDidCatch(_error: Error, _errorInfo: ErrorInfo) {
    // React still requires this hook for class error boundaries.
  }

  componentDidUpdate(previousProps: RouteErrorBoundaryProps) {
    if (
      this.state.hasError &&
      previousProps.resetKey !== this.props.resetKey
    ) {
      this.setState({ hasError: false })
    }
  }

  render() {
    if (this.state.hasError) {
      return <ErrorState message="Workbench route failed to render." />
    }
    return this.props.children
  }
}
