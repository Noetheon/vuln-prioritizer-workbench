import { Link } from "@/lib/router"
import { CheckCircle2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import type { ProjectUrlSearch } from "@/workbench/selected-project-search"

type DashboardKeyTakeawaysProps = {
  items: readonly string[]
  projectSearch: ProjectUrlSearch
}

export function DashboardKeyTakeaways({
  items,
  projectSearch,
}: DashboardKeyTakeawaysProps) {
  return (
    <aside aria-label="Key takeaways" className="dashboard-key-takeaways">
      <div>
        <p className="text-sm font-semibold text-[var(--vpw-text-primary)]">
          Key takeaways
        </p>
        <ul className="mt-4 flex flex-col gap-3">
          {items.map((item) => (
            <li className="flex gap-2 text-xs" key={item}>
              <CheckCircle2
                aria-hidden="true"
                className="mt-0.5 size-3.5 shrink-0 text-[var(--vpw-green)]"
              />
              <span className="leading-relaxed text-[var(--vpw-text-secondary)]">
                {item}
              </span>
            </li>
          ))}
        </ul>
      </div>
      <Button asChild className="w-fit" size="sm" variant="outline">
        <Link search={projectSearch} to="/findings">
          Go to Triage
        </Link>
      </Button>
    </aside>
  )
}
