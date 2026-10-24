package rules

import java.net.IDN

private const val MAX_DOMAIN_LENGTH = 253

private val LABEL_REGEX = Regex("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")

/** Lowercase ASCII hostname (IDN converted to punycode), or null if [raw] is not a valid hostname. */
fun normalizeDomain(raw: String): String? {
    val trimmed = raw.trim().lowercase().removeSuffix(".")
    if (trimmed.isEmpty()) return null

    val ascii = try {
        IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES).lowercase()
    } catch (_: IllegalArgumentException) {
        return null
    }

    if (ascii.length > MAX_DOMAIN_LENGTH) return null

    val labels = ascii.split('.')
    if (!labels.all(LABEL_REGEX::matches)) return null
    if (!labels.filter { it.startsWith("xn--") }.all(::isValidPunycode)) return null

    return ascii
}

// IDN.toUnicode returns broken punycode unchanged instead of failing, so require a real round trip
private fun isValidPunycode(label: String): Boolean =
    try {
        val unicode = IDN.toUnicode(label, IDN.USE_STD3_ASCII_RULES)
        unicode != label && IDN.toASCII(unicode, IDN.USE_STD3_ASCII_RULES) == label
    } catch (_: IllegalArgumentException) {
        false
    }

/** Domains never allowed in the output. Mihomo syntax: `a.com` matches itself, `+.a.com` also its subdomains. */
class Denylist(lines: List<String>) {

    private val exact = mutableSetOf<String>()
    private val suffixes = mutableSetOf<String>()

    init {
        for (line in lines.map { it.substringBefore('#').trim() }.filter { it.isNotEmpty() }) {
            val domain = normalizeDomain(line.removePrefix(WILDCARD_PREFIX))
            requireNotNull(domain) { "Invalid denylist entry: $line" }

            if (line.startsWith(WILDCARD_PREFIX)) {
                suffixes += domain
            } else {
                exact += domain
            }
        }
    }

    fun matches(domain: String): Boolean =
        domain in exact || suffixes.any { domain == it || domain.endsWith(".$it") }

    companion object {
        private const val WILDCARD_PREFIX = "+."
    }

}
