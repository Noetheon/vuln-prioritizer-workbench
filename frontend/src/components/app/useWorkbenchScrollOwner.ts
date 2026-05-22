import {
  type KeyboardEvent,
  type RefObject,
  type WheelEvent,
  useCallback,
  useEffect,
  useRef,
} from "react"

const scrollableOverflowValues = new Set(["auto", "scroll", "overlay"])
const scrollExemptSelector =
  '[role="dialog"], [data-radix-popper-content-wrapper], [data-vpw-scroll-lock-exempt]'
const wheelDeltaScale = 0.42
const wheelDeltaMaxViewportRatio = 0.32
const wheelDeltaMinCap = 96
const wheelDeltaMaxCap = 260
const smoothScrollEasing = 0.22

function normalizedWheelDeltaY(
  event: WheelEvent<HTMLElement>,
  content: HTMLElement,
) {
  if (event.deltaMode === 1) return event.deltaY * 16
  if (event.deltaMode === 2) return event.deltaY * content.clientHeight
  return event.deltaY
}

function nearestScrollableElement(target: EventTarget | null) {
  if (!(target instanceof Element)) return null
  let current: Element | null = target
  while (current instanceof HTMLElement) {
    const style = window.getComputedStyle(current)
    if (
      scrollableOverflowValues.has(style.overflowY) &&
      current.scrollHeight > current.clientHeight + 1
    ) {
      return current
    }
    current = current.parentElement
  }
  return null
}

function canScrollInDirection(element: HTMLElement, deltaY: number) {
  const maxScrollTop = element.scrollHeight - element.clientHeight
  if (maxScrollTop <= 1) return false
  if (deltaY < 0) return element.scrollTop > 0
  if (deltaY > 0) return element.scrollTop < maxScrollTop - 1
  return false
}

function cappedWheelDelta(deltaY: number, content: HTMLElement) {
  const scaledDelta = deltaY * wheelDeltaScale
  const viewportCap = content.clientHeight * wheelDeltaMaxViewportRatio
  const deltaCap = Math.max(
    wheelDeltaMinCap,
    Math.min(wheelDeltaMaxCap, viewportCap),
  )
  return Math.sign(scaledDelta) * Math.min(Math.abs(scaledDelta), deltaCap)
}

function clampedScrollTop(element: HTMLElement, scrollTop: number) {
  const maxScrollTop = Math.max(0, element.scrollHeight - element.clientHeight)
  return Math.min(maxScrollTop, Math.max(0, scrollTop))
}

function prefersReducedMotion() {
  return (
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  )
}

function keyboardDeltaY(event: KeyboardEvent<HTMLElement>, content: HTMLElement) {
  switch (event.key) {
    case "ArrowDown":
      return 56
    case "ArrowUp":
      return -56
    case "End":
      return content.scrollHeight - content.clientHeight - content.scrollTop
    case "Home":
      return -content.scrollTop
    case "PageDown":
      return content.clientHeight * 0.88
    case "PageUp":
      return content.clientHeight * -0.88
    default:
      return 0
  }
}

function isFormControlTarget(target: EventTarget | null) {
  if (!(target instanceof Element)) return false
  const tagName = target.tagName.toLowerCase()
  return (
    tagName === "input" ||
    tagName === "select" ||
    tagName === "textarea" ||
    target.closest('[contenteditable="true"]') !== null
  )
}

export function useWorkbenchScrollOwner(
  contentRef: RefObject<HTMLElement | null>,
) {
  const animationFrameRef = useRef<number | null>(null)
  const animationElementRef = useRef<HTMLElement | null>(null)
  const targetScrollTopRef = useRef<number | null>(null)

  const cancelSmoothScroll = useCallback(() => {
    if (
      typeof window !== "undefined" &&
      animationFrameRef.current !== null
    ) {
      window.cancelAnimationFrame(animationFrameRef.current)
    }
    animationFrameRef.current = null
    animationElementRef.current = null
    targetScrollTopRef.current = null
  }, [])

  const smoothScrollElementBy = useCallback(
    (element: HTMLElement, deltaY: number) => {
      const currentTarget =
        animationElementRef.current === element
          ? (targetScrollTopRef.current ?? element.scrollTop)
          : element.scrollTop
      const nextTarget = clampedScrollTop(element, currentTarget + deltaY)
      if (Math.abs(nextTarget - element.scrollTop) < 1) return false

      if (prefersReducedMotion()) {
        cancelSmoothScroll()
        element.scrollTop = nextTarget
        return true
      }

      animationElementRef.current = element
      targetScrollTopRef.current = nextTarget

      if (animationFrameRef.current !== null) return true

      const animate = () => {
        const animationElement = animationElementRef.current
        const targetScrollTop = targetScrollTopRef.current
        if (!animationElement || targetScrollTop === null) {
          cancelSmoothScroll()
          return
        }

        const distance = targetScrollTop - animationElement.scrollTop
        if (Math.abs(distance) < 0.75) {
          animationElement.scrollTop = targetScrollTop
          cancelSmoothScroll()
          return
        }

        animationElement.scrollTop += distance * smoothScrollEasing
        animationFrameRef.current = window.requestAnimationFrame(animate)
      }

      animationFrameRef.current = window.requestAnimationFrame(animate)
      return true
    },
    [cancelSmoothScroll],
  )

  useEffect(() => cancelSmoothScroll, [cancelSmoothScroll])

  const onWheelCapture = useCallback(
    (event: WheelEvent<HTMLElement>) => {
      const content = contentRef.current
      if (!content || event.defaultPrevented || event.deltaY === 0) return
      const target = event.target
      if (!(target instanceof Element)) return
      if (target.closest(scrollExemptSelector)) return

      const deltaY = normalizedWheelDeltaY(event, content)
      const scrollableTarget = nearestScrollableElement(target)
      if (
        scrollableTarget &&
        scrollableTarget !== content &&
        canScrollInDirection(scrollableTarget, deltaY)
      ) {
        return
      }
      if (!smoothScrollElementBy(content, cappedWheelDelta(deltaY, content))) {
        return
      }

      event.preventDefault()
    },
    [contentRef, smoothScrollElementBy],
  )

  const onKeyDownCapture = useCallback(
    (event: KeyboardEvent<HTMLElement>) => {
      if (
        event.defaultPrevented ||
        event.altKey ||
        event.ctrlKey ||
        event.metaKey ||
        isFormControlTarget(event.target)
      ) {
        return
      }
      const target = event.target
      if (target instanceof Element && target.closest(scrollExemptSelector)) {
        return
      }

      const content = contentRef.current
      if (!content) return
      const deltaY = keyboardDeltaY(event, content)
      if (deltaY === 0 || !smoothScrollElementBy(content, deltaY)) return

      event.preventDefault()
    },
    [contentRef, smoothScrollElementBy],
  )

  return { onKeyDownCapture, onWheelCapture }
}
