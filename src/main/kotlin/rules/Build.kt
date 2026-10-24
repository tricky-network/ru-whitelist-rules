package rules

import kotlin.math.abs

private const val PERCENT = 100

/** A sanity gate rejected the build; the message lists every failed check. */
class GateFailure(message: String) : Exception(message)

/** Raw upstream lines, before any validation. */
data class Inputs(val cidrs: List<String>, val domains: List<String>, val geoip: List<String>)

/** Entry counts of the last published version, for the size gate. */
data class Previous(val cidrs: Int, val domains: Int)

/** Lists ready for publishing, plus what was rejected on the way. */
data class BuildResult(
    val cidrs: List<Cidr>,
    val domains: List<String>,
    val invalidCidrs: List<String>,
    val invalidDomains: List<String>,
    val subnets: SubnetReport,
)

/** Turns upstream lines into publishable lists, throwing [GateFailure] if any sanity gate fails. */
fun build(
    inputs: Inputs,
    denylist: Denylist,
    previous: Previous?,
    maxChangePercent: Int,
    allowSizeChange: Boolean,
): BuildResult {
    val domainLines = inputs.domains.map { it.trim() }.filter { it.isNotEmpty() }
    val domains = domainLines.mapNotNull(::normalizeDomain).distinct().sorted()
    val invalidDomains = domainLines.filter { normalizeDomain(it) == null }

    val cidrLines = inputs.cidrs.map { it.trim() }.filter { it.isNotEmpty() }
    val invalidCidrs = cidrLines.filter { Cidr.parse(it) == null }

    // ru.list mixes IPv4 and IPv6; only IPv4 matters here
    val geo = inputs.geoip.mapNotNull { Cidr.parse(it.trim()) }
    val (cidrs, subnets) = clip(cidrLines.mapNotNull(Cidr::parse), geo)

    val errors = mutableListOf<String>()
    val denied = domains.filter(denylist::matches)

    if (denied.isNotEmpty())
        errors += "Upstream domains hit the denylist: ${denied.joinToString()}"

    if (domains.isEmpty())
        errors += "Domain list is empty"

    if (cidrs.isEmpty())
        errors += "Subnet list is empty"

    if (previous != null && !allowSizeChange) {
        computeSizeError("Domain", previous.domains, domains.size, maxChangePercent)?.let(errors::add)
        computeSizeError("Subnet", previous.cidrs, cidrs.size, maxChangePercent)?.let(errors::add)
    }

    if (errors.isNotEmpty())
        throw GateFailure(errors.joinToString("\n"))

    return BuildResult(cidrs, domains, invalidCidrs, invalidDomains, subnets)
}

private fun computeSizeError(what: String, before: Int, after: Int, maxPercent: Int): String? {
    if (before == 0) return null
    if (abs(after - before) * PERCENT <= maxPercent * before) return null

    val percent = (after - before) * PERCENT / before
    return "$what list size changed by $percent% ($before -> $after), limit is ±$maxPercent%; " +
        "rerun manually with allow_size_change if this is expected"
}
