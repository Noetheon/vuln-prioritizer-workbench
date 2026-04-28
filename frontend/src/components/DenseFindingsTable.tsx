import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef
} from "@tanstack/react-table";
import { Link } from "react-router-dom";
import { useMemo } from "react";

import type { Finding } from "../api/types";
import { governanceLabel, formatPercent, formatScore } from "../lib/format";
import { Badge, PriorityBadge } from "./Badges";

interface DenseFindingsTableProps {
  findings: Finding[];
  projectId: string;
  maxRows?: number;
  density?: "full" | "summary";
  emptyMessage?: string;
}

export default function DenseFindingsTable({
  findings,
  projectId,
  maxRows,
  density = "full",
  emptyMessage = "No findings imported."
}: DenseFindingsTableProps) {
  const rows = useMemo(() => (maxRows ? findings.slice(0, maxRows) : findings), [findings, maxRows]);
  const columns = useMemo<ColumnDef<Finding>[]>(
    () => {
      const triageColumns: ColumnDef<Finding>[] = [
        {
          header: "Rank",
          accessorKey: "operational_rank",
          cell: ({ row }) => <span className="rank-cell">{row.original.operational_rank}</span>
        },
        {
          header: "Priority",
          accessorKey: "priority",
          cell: ({ row }) => <PriorityBadge priority={row.original.priority} />
        },
        {
          header: "CVE",
          accessorKey: "cve_id",
          cell: ({ row }) => (
            <Link className="table-link" to={`/projects/${projectId}/findings/${row.original.id}`}>
              {row.original.cve_id}
            </Link>
          )
        },
        {
          header: "Component",
          accessorKey: "component",
          cell: ({ row }) => (
            <span>
              {row.original.component ?? "N.A."}
              {row.original.component_version ? <small className="subtle-cell"> {row.original.component_version}</small> : null}
            </span>
          )
        },
        {
          header: "Asset / Service",
          id: "asset-service",
          cell: ({ row }) => (
            <span>
              {row.original.asset ?? "N.A."}
              {row.original.service ? <small className="subtle-cell"> {row.original.service}</small> : null}
            </span>
          )
        },
        {
          header: "Owner",
          accessorKey: "owner",
          cell: ({ row }) => row.original.owner ?? "N.A."
        },
        {
          header: "EPSS",
          accessorKey: "epss",
          cell: ({ row }) => formatPercent(row.original.epss)
        },
        {
          header: "CVSS",
          accessorKey: "cvss_base_score",
          cell: ({ row }) => formatScore(row.original.cvss_base_score)
        }
      ];

      if (density === "summary") {
        return triageColumns;
      }

      return [
        ...triageColumns,
        {
          header: "Status",
          accessorKey: "status",
          cell: ({ row }) => <Badge tone={row.original.status === "open" ? "critical" : "neutral"}>{row.original.status}</Badge>
        },
        {
          header: "Governance",
          id: "governance",
          cell: ({ row }) =>
            row.original.waiver_status || row.original.waived
              ? `waiver ${governanceLabel(row.original.waiver_status ?? "active")}`
              : row.original.suppressed_by_vex
                ? "VEX suppressed"
                : row.original.under_investigation
                  ? "VEX review"
                  : "N.A."
        }
      ];
    },
    [density, projectId]
  );
  const table = useReactTable({
    data: rows,
    columns,
    getCoreRowModel: getCoreRowModel()
  });

  if (rows.length === 0) {
    return <div className="table-empty">{emptyMessage}</div>;
  }

  return (
    <div className="dense-table-wrap">
      <table className={`dense-table dense-table-${density}`}>
        <caption className="sr-only">Prioritized vulnerability findings</caption>
        <thead>
          {table.getHeaderGroups().map((headerGroup) => (
            <tr key={headerGroup.id}>
              {headerGroup.headers.map((header) => (
                <th key={header.id} scope="col">
                  {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map((row) => (
            <tr key={row.id}>
              {row.getVisibleCells().map((cell) =>
                cell.column.id === "cve_id" ? (
                  <th className="row-header" key={cell.id} scope="row">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </th>
                ) : (
                  <td key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>
                )
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
