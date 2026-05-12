import {
  type AnchorHTMLAttributes,
  type MouseEvent,
  type ReactNode,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react"

type SearchPrimitive = string | number | boolean | null | undefined
type SearchRecord = Record<string, SearchPrimitive>
type SearchValue = SearchRecord | string | URLSearchParams
type SearchInput = SearchValue | (() => SearchValue)

export type RouterLocation = {
  pathname: string
  searchStr: string
}

type NavigateOptions = {
  params?: Record<string, SearchPrimitive>
  replace?: boolean
  search?: SearchInput
  to?: string
}

type RouterContextValue = {
  location: RouterLocation
  navigate: (options: NavigateOptions | string) => Promise<void>
  params: Record<string, string>
}

const RouterContext = createContext<RouterContextValue | null>(null)

function readLocation(): RouterLocation {
  if (typeof window === "undefined") {
    return { pathname: "/", searchStr: "" }
  }
  return {
    pathname: window.location.pathname || "/",
    searchStr: window.location.search,
  }
}

function serializeSearch(search: SearchInput | undefined): string {
  if (!search) return ""
  const resolved = typeof search === "function" ? search() : search
  if (typeof resolved === "string") {
    return resolved.startsWith("?") ? resolved.slice(1) : resolved
  }
  const source = resolved instanceof URLSearchParams
    ? resolved
    : new URLSearchParams()
  if (!(resolved instanceof URLSearchParams)) {
    for (const [key, value] of Object.entries(resolved)) {
      if (value !== undefined && value !== null && value !== "") {
        source.set(key, String(value))
      }
    }
  }
  return source.toString()
}

function pathWithParams(path: string, params?: Record<string, SearchPrimitive>) {
  if (!params) return path
  return Object.entries(params).reduce((currentPath, [key, value]) => {
    const encodedValue = encodeURIComponent(String(value ?? ""))
    return currentPath.replace(`$${key}`, encodedValue).replace(`:${key}`, encodedValue)
  }, path)
}

export function hrefForRoute({
  params,
  search,
  to,
}: {
  params?: Record<string, SearchPrimitive>
  search?: SearchInput
  to: string
}) {
  const path = pathWithParams(to, params)
  const query = serializeSearch(search)
  return query ? `${path}?${query}` : path
}

export function BrowserRouter({ children }: { children: ReactNode }) {
  const [location, setLocation] = useState(readLocation)

  useEffect(() => {
    function handleNavigation() {
      setLocation(readLocation())
    }
    window.addEventListener("popstate", handleNavigation)
    window.addEventListener("vpw:navigation", handleNavigation)
    return () => {
      window.removeEventListener("popstate", handleNavigation)
      window.removeEventListener("vpw:navigation", handleNavigation)
    }
  }, [])

  const navigate = useCallback(
    async (options: NavigateOptions | string) => {
      if (typeof window === "undefined") return
      const nextOptions = typeof options === "string" ? { to: options } : options
      const nextPath = hrefForRoute({
        params: nextOptions.params,
        search: nextOptions.search,
        to: nextOptions.to ?? window.location.pathname,
      })
      const currentPath = `${window.location.pathname}${window.location.search}`
      if (nextPath === currentPath) return
      if (nextOptions.replace) {
        window.history.replaceState(null, "", nextPath)
      } else {
        window.history.pushState(null, "", nextPath)
      }
      window.dispatchEvent(new Event("vpw:navigation"))
    },
    [],
  )

  const value = useMemo<RouterContextValue>(
    () => ({ location, navigate, params: {} }),
    [location, navigate],
  )

  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>
}

export function RouteParamsProvider({
  children,
  params,
}: {
  children: ReactNode
  params: Record<string, string>
}) {
  const context = useRouterContext()
  const value = useMemo<RouterContextValue>(
    () => ({ ...context, params }),
    [context, params],
  )
  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>
}

export function useLocation() {
  return useRouterContext().location
}

export function useNavigate() {
  return useRouterContext().navigate
}

export function useParams<TParams extends Record<string, string> = Record<string, string>>(
  _options?: unknown,
) {
  return useRouterContext().params as TParams
}

type LinkProps = Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href"> & {
  params?: Record<string, SearchPrimitive>
  search?: SearchInput
  to: string
}

export function Link({
  onClick,
  params,
  search,
  to,
  ...props
}: LinkProps) {
  const navigate = useNavigate()
  const href = hrefForRoute({ params, search, to })

  function handleClick(event: MouseEvent<HTMLAnchorElement>) {
    onClick?.(event)
    if (
      event.defaultPrevented ||
      event.button !== 0 ||
      event.metaKey ||
      event.altKey ||
      event.ctrlKey ||
      event.shiftKey ||
      props.target
    ) {
      return
    }
    event.preventDefault()
    void navigate({ params, search, to })
  }

  return <a href={href} onClick={handleClick} {...props} />
}

function useRouterContext() {
  const context = useContext(RouterContext)
  if (!context) {
    throw new Error("Router context is not mounted")
  }
  return context
}
