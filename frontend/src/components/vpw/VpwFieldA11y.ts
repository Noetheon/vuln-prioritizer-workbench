import {
  Children,
  cloneElement,
  isValidElement,
  type ReactElement,
  type ReactNode,
} from "react"

type FieldControlProps = {
  children?: ReactNode
  id?: string
  "aria-describedby"?: string
  "aria-errormessage"?: string
  "aria-invalid"?: boolean | "true" | "false"
  "aria-required"?: boolean | "true" | "false"
}

export type FieldControlA11y = {
  controlId: string
  describedBy: string | undefined
  errorId: string | undefined
  invalid: boolean
  required: boolean
}

type FieldControlElementType = ReactElement<FieldControlProps>["type"]

const nativeFieldControlNames = new Set(["button", "input", "select", "textarea"])
const componentFieldControlNames = new Set([
  "Input",
  "SelectTrigger",
  "Textarea",
  "VpwFileInput",
  "VpwSearchControl",
  "VpwSelectControl",
])

function elementTypeName(type: FieldControlElementType): string | undefined {
  if (typeof type === "string") return type
  if (typeof type === "function") {
    const namedType = type as { displayName?: string; name?: string }
    return namedType.displayName ?? namedType.name
  }
  if (typeof type === "object" && type !== null) {
    const namedType = type as {
      displayName?: string
      name?: string
      render?: { displayName?: string; name?: string }
    }
    return (
      namedType.displayName ??
      namedType.name ??
      namedType.render?.displayName ??
      namedType.render?.name
    )
  }
  return undefined
}

export function mergeIdRefs(...values: Array<string | undefined>) {
  const ids = values
    .flatMap((value) => value?.split(/\s+/) ?? [])
    .filter(Boolean)
  return ids.length > 0 ? [...new Set(ids)].join(" ") : undefined
}

function isFieldControlElement(
  element: ReactElement<FieldControlProps>,
  controlId: string,
) {
  if (element.props.id === controlId) return true

  const name = elementTypeName(element.type)
  if (!name) return false
  return nativeFieldControlNames.has(name) || componentFieldControlNames.has(name)
}

function controlPropsFor(
  props: FieldControlProps,
  { controlId, describedBy, errorId, invalid, required }: FieldControlA11y,
): FieldControlProps {
  const nextProps: FieldControlProps = {
    "aria-describedby": mergeIdRefs(props["aria-describedby"], describedBy),
    id: controlId,
  }

  if (required) nextProps["aria-required"] = true
  if (invalid) {
    nextProps["aria-invalid"] = true
    if (errorId) nextProps["aria-errormessage"] = errorId
  }

  return nextProps
}

export function withFieldControlA11y(
  children: ReactNode,
  a11y: FieldControlA11y,
) {
  let controlEnhanced = false

  function visit(child: ReactNode): ReactNode {
    if (controlEnhanced || !isValidElement<FieldControlProps>(child)) {
      return child
    }

    if (isFieldControlElement(child, a11y.controlId)) {
      controlEnhanced = true
      return cloneElement(child, controlPropsFor(child.props, a11y))
    }

    if (!child.props.children) return child

    return cloneElement(child, {
      children: Children.map(child.props.children, visit),
    } satisfies Partial<FieldControlProps>)
  }

  return Children.map(children, visit)
}
