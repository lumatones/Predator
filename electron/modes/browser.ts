import { ScanResult, yieldToEventLoop } from '../types'
import { ALL_CHEAT_KEYWORDS } from '../heuristic'
import { scanAllBrowsers } from '../browser-history'

/**
 * Scan browser history for cheat-related keywords
 */
export async function scanBrowserHistory(keywords?: string[]): Promise<ScanResult[]> {
  const kw = keywords || ALL_CHEAT_KEYWORDS
  const results: ScanResult[] = []

  try {
    // Use sql.js-based structured browser history parser
    const browserResults = await scanAllBrowsers(kw)

    for (const br of browserResults) {
      if (br.entries.length === 0) continue

      // Group entries by keyword match for the ScanResult.matches format
      const matchSet = new Set<string>()
      let maxRisk: 'low' | 'medium' | 'high' = 'low'
      let matchCount = 0

      for (const entry of br.entries) {
        const url = entry.url.toLowerCase()
        const title = entry.title.toLowerCase()
        for (const keyword of kw) {
          if (url.includes(keyword.toLowerCase()) || title.includes(keyword.toLowerCase())) {
            matchSet.add(`browser:${keyword}`)
            matchCount++
          }
        }
      }

      if (matchSet.size > 0) {
        if (matchCount >= 5) maxRisk = 'high'
        else if (matchCount >= 3) maxRisk = 'medium'

        results.push({
          path: br.path,
          fileName: `История (${br.browser})`,
          type: 'browser',
          risk: maxRisk,
          matches: Array.from(matchSet).slice(0, 15),
          size: br.entries.length,
          modifiedAt: br.entries[0]?.lastVisitTime || new Date().toISOString(),
        })

        // Add detail entries for high-value findings (URLs)
        const suspiciousEntries = br.entries.filter(e => {
          const url = e.url.toLowerCase()
          const title = e.title.toLowerCase()
          return kw.some(k => url.includes(k.toLowerCase()) || title.includes(k.toLowerCase()))
        })

        for (const entry of suspiciousEntries.slice(0, 8)) {
          const urlMatch = kw.find(k =>
            entry.url.toLowerCase().includes(k.toLowerCase()) ||
            entry.title.toLowerCase().includes(k.toLowerCase())
          )
          results.push({
            path: entry.url,
            fileName: `[${br.browser}] ${entry.title.slice(0, 60)}`,
            type: 'browser',
            risk: maxRisk,
            matches: [`browser:${urlMatch || 'suspicious'}`, `visited:${entry.lastVisitTime.slice(0, 10)}`, `count:${entry.visitCount}`],
            size: entry.url.length,
            modifiedAt: entry.lastVisitTime,
          })
        }
      }
    }
  } catch (err) {
    console.error('Browser history scan error:', err)
  }

  await yieldToEventLoop()
  return results
}
