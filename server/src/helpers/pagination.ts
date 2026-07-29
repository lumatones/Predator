/**
 * Predator Server — Pagination Helper
 *
 * Parses ?page= and ?limit= from query params and returns
 * SQL-ready offset/limit values + pagination HTTP headers.
 *
 * BACKWARD COMPATIBLE: Body format stays the same.
 * Pagination info is communicated via response headers:
 *   X-Total-Count: 150
 *   X-Page: 3
 *   X-Limit: 50
 *   X-Total-Pages: 3
 *
 * Usage:
 *   const { offset, limit } = paginate(req.query)
 *   setPaginationHeaders(res, page, limit)
 *   const rows = await query('SELECT ... LIMIT ? OFFSET ?', [limit, offset])
 *   return res.json(rows)
 */

import type { Response } from 'express'

export interface PaginationParams {
  offset: number
  limit: number
  page: number
}

const MAX_LIMIT = 500
const DEFAULT_LIMIT = 50

/**
 * Parse pagination from query params.
 * Returns SQL-ready offset/limit values.
 */
export function paginate(query: Record<string, any>): PaginationParams {
  let page = parseInt(String(query.page || ''), 10)
  let limit = parseInt(String(query.limit || ''), 10)

  if (isNaN(page) || page < 1) page = 1
  if (isNaN(limit) || limit < 1) limit = DEFAULT_LIMIT
  if (limit > MAX_LIMIT) limit = MAX_LIMIT

  const offset = (page - 1) * limit

  return { offset, limit, page }
}

/**
 * Set pagination response headers for backward-compatible REST API.
 * Body format unchanged — clients that don't read headers ignore them.
 *
 * @param res - Express Response
 * @param page - current page number
 * @param limit - items per page
 * @param total - total number of items (optional for endpoints with unknown total)
 */
export function setPaginationHeaders(
  res: Response,
  page: number,
  limit: number,
  total?: number,
): void {
  res.setHeader('X-Page', String(page))
  res.setHeader('X-Limit', String(limit))

  if (total !== undefined) {
    const totalPages = Math.max(1, Math.ceil(total / limit))
    res.setHeader('X-Total-Count', String(total))
    res.setHeader('X-Total-Pages', String(totalPages))
  }
}

/**
 * Count total rows for a filtered table.
 * Parameterized query — safe from SQL injection.
 *
 * @param queryFn - the database query function
 * @param table - table name (raw table name — only used in FROM clause)
 * @param whereClause - everything after WHERE, with ? placeholders (e.g. "status = ?")
 * @param params - params for the WHERE clause
 */
export async function countTotal(
  queryFn: (sql: string, params?: any[]) => Promise<any[]>,
  table: string,
  whereClause?: string,
  params?: any[],
): Promise<number> {
  try {
    const sql = `SELECT COUNT(*) AS total FROM ${table}${whereClause ? ` WHERE ${whereClause}` : ''}`
    const rows = await queryFn(sql, params || [])
    return rows[0]?.total ?? 0
  } catch {
    return 0
  }
}
