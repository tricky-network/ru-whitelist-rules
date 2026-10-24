package rules

private const val ADDRESS_BITS = 32
private const val MAX_ADDRESS = 0xFFFFFFFFL
private const val MAX_OCTET = 255
private const val OCTET_BITS = 8
private const val TOP_DROPPED_LIMIT = 10

/** Inclusive IPv4 range, in Longs so that /0 fits; [cidrs] is its minimal CIDR cover. */
data class Range(val first: Long, val last: Long) {

    val cidrs: List<Cidr>
        get() {
            val cidrs = mutableListOf<Cidr>()
            var start = first

            while (start <= last) {
                var prefix = ADDRESS_BITS - minOf(ADDRESS_BITS, start.countTrailingZeroBits())
                while (start + computeBlockSize(prefix) - 1 > last) prefix++

                cidrs += Cidr(start, prefix)
                start += computeBlockSize(prefix)
            }

            return cidrs
        }

    val size: Long
        get() = last - first + 1

}

/** IPv4 subnet. [parse] takes only canonical `a.b.c.d/n` and clears host bits; anything else, IPv6 too, is null. */
data class Cidr(val address: Long, val prefix: Int) {

    override fun toString(): String {
        val shifts = ADDRESS_BITS - OCTET_BITS downTo 0 step OCTET_BITS
        val octets = shifts.map { (address shr it).toInt() and MAX_OCTET }
        return "${octets.joinToString(".")}/$prefix"
    }

    val range: Range
        get() = Range(address, address + computeBlockSize(prefix) - 1)

    companion object {

        fun parse(value: String): Cidr? {
            val parts = value.split('/')
            if (parts.size != 2) return null

            val prefix = parseCanonicalInt(parts[1], 0..ADDRESS_BITS) ?: return null
            val octets = parts[0].split('.')
            if (octets.size != ADDRESS_BITS / OCTET_BITS) return null

            var address = 0L
            for (octet in octets) {
                val value = parseCanonicalInt(octet, 0..MAX_OCTET) ?: return null
                address = address shl OCTET_BITS or value.toLong()
            }

            val mask = MAX_ADDRESS shl (ADDRESS_BITS - prefix) and MAX_ADDRESS
            return Cidr(address and mask, prefix)
        }

        private fun parseCanonicalInt(value: String, bounds: IntRange): Int? =
            value.toIntOrNull()?.takeIf { it in bounds && it.toString() == value }

    }

}

/** What [clip] did to the upstream subnets; [topDropped] holds the largest dropped ones. */
data class SubnetReport(val dropped: Int, val full: Int, val topDropped: List<Cidr>, val trimmed: Int)

/** Clips every whitelist subnet to [geo] and aggregates what is left. */
fun clip(whitelist: List<Cidr>, geo: List<Cidr>): Pair<List<Cidr>, SubnetReport> {
    val geoRanges = merge(geo.map { it.range })
    val kept = mutableListOf<Range>()
    val dropped = mutableListOf<Cidr>()
    var full = 0
    var trimmed = 0

    for (cidr in whitelist.distinct()) {
        val parts = intersect(cidr.range, geoRanges)
        kept += parts

        when (parts.sumOf { it.size }) {
            0L -> dropped += cidr
            cidr.range.size -> full++
            else -> trimmed++
        }
    }

    val topDropped = dropped.sortedWith(compareBy({ it.prefix }, { it.address })).take(TOP_DROPPED_LIMIT)
    return merge(kept).flatMap { it.cidrs } to SubnetReport(dropped.size, full, topDropped, trimmed)
}

/** Sorts ranges and merges overlapping and adjacent ones. */
fun merge(ranges: List<Range>): List<Range> {
    val merged = mutableListOf<Range>()

    for (range in ranges.sortedBy { it.first }) {
        val last = merged.lastOrNull()
        if (last != null && range.first <= last.last + 1) {
            merged[merged.lastIndex] = Range(last.first, maxOf(last.last, range.last))
        } else {
            merged += range
        }
    }

    return merged
}

/** Parts of [range] covered by [merged], which must come from [merge]. */
fun intersect(range: Range, merged: List<Range>): List<Range> {
    val parts = mutableListOf<Range>()

    // the comparator never returns 0, so binarySearch gives -(first range ending at or after range.first) - 1
    var index = -merged.binarySearch { if (it.last < range.first) -1 else 1 } - 1

    while (index < merged.size && merged[index].first <= range.last) {
        parts += Range(maxOf(range.first, merged[index].first), minOf(range.last, merged[index].last))
        index++
    }

    return parts
}

private fun computeBlockSize(prefix: Int): Long =
    1L shl (ADDRESS_BITS - prefix)
