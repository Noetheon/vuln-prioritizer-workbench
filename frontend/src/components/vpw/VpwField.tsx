import {
  useId,
  type ComponentPropsWithoutRef,
  type ReactNode,
} from "react"

import { cn } from "@/lib/utils"
import { mergeIdRefs, withFieldControlA11y } from "./VpwFieldA11y"

export type FieldOrientation = "vertical" | "horizontal" | "responsive"

export type VpwFieldProps = {
  children: ReactNode
  label: string
  className?: string
  description?: ReactNode
  error?: ReactNode
  htmlFor?: string
  required?: boolean
}

const fieldOrientationClass: Record<FieldOrientation, string> = {
  vertical: "flex-col",
  horizontal: "flex-row items-center",
  responsive: "flex-col sm:flex-row sm:items-center",
}

export type FieldProps = ComponentPropsWithoutRef<"div"> & {
  orientation?: FieldOrientation
}

export type FieldErrorProps = ComponentPropsWithoutRef<"div"> & {
  errors?: Array<{ message?: string } | undefined>
}

export function Field({
  className,
  orientation = "vertical",
  ...props
}: FieldProps) {
  return (
    <div
      data-orientation={orientation}
      data-slot="field"
      className={cn(
        "vpw-field group/field flex w-full gap-1.5 data-[invalid=true]:text-[var(--vpw-red)]",
        fieldOrientationClass[orientation],
        className,
      )}
      {...props}
    />
  )
}

export function FieldLabel({
  className,
  ...props
}: ComponentPropsWithoutRef<"label">) {
  return (
    // biome-ignore lint/a11y/noLabelWithoutControl: FieldLabel is a primitive; VpwField passes htmlFor when the owning control has an id.
    <label
      data-slot="field-label"
      className={cn(
        "vpw-field-label flex w-fit items-center gap-1 group-data-[disabled=true]/field:opacity-50",
        className,
      )}
      {...props}
    />
  )
}

export function FieldDescription({
  className,
  ...props
}: ComponentPropsWithoutRef<"p">) {
  return (
    <p
      data-slot="field-description"
      className={cn(
        "text-xs leading-5 text-[var(--vpw-text-muted)]",
        className,
      )}
      {...props}
    />
  )
}

export function FieldError({
  children,
  className,
  errors,
  ...props
}: FieldErrorProps) {
  const messages = [
    ...new Set(
      errors
        ?.map((error) => error?.message)
        .filter((message): message is string => Boolean(message)) ?? [],
    ),
  ]
  const content =
    children ??
    (messages.length === 1 ? (
      messages[0]
    ) : messages.length > 1 ? (
      <ul className="ml-4 flex list-disc flex-col gap-1">
        {messages.map((message) => (
          <li key={message}>{message}</li>
        ))}
      </ul>
    ) : null)

  if (!content) return null

  return (
    <div
      data-slot="field-error"
      role="alert"
      className={cn("text-xs leading-5 text-[var(--vpw-red)]", className)}
      {...props}
    >
      {content}
    </div>
  )
}

export function VpwField({
  children,
  className,
  description,
  error,
  htmlFor,
  label,
  required = false,
}: VpwFieldProps) {
  const generatedId = useId()
  const labelId = `${generatedId}-label`
  const descriptionId = description ? `${generatedId}-description` : undefined
  const errorId = error ? `${generatedId}-error` : undefined
  const controlId = htmlFor ?? `${generatedId}-control`
  const describedBy = mergeIdRefs(descriptionId, errorId)
  const fieldChildren = withFieldControlA11y(children, {
    controlId,
    describedBy,
    errorId,
    invalid: Boolean(error),
    required,
  })

  return (
    <Field
      className={className}
      data-invalid={error ? true : undefined}
    >
      <FieldLabel htmlFor={controlId} id={labelId}>
        {label}
        {required ? (
          <span className="ml-1 text-[var(--vpw-red)]" aria-hidden="true">
            *
          </span>
        ) : null}
      </FieldLabel>
      {fieldChildren}
      {description ? (
        <FieldDescription id={descriptionId}>{description}</FieldDescription>
      ) : null}
      {error ? <FieldError id={errorId}>{error}</FieldError> : null}
    </Field>
  )
}
