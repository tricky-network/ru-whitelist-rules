package rules

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

internal class Ipv4Test {

    private val invalidCidrs = listOf(
        "", "1.2.3.4", "1.2.3/24", "1.2.3.4/33", "1.2.3.256/24", "01.2.3.4/24", "1.2.3.4/024",
        "+1.2.3.4/24", "1.2.3.4/-1", "2a00::/32", "a.b.c.d/8", "1.2.3.4/24/1",
    )

    @Test
    fun `should parse canonical cidrs and clear host bits`() {
        assertEquals("0.0.0.0/0", cidr("0.0.0.0/0").toString())
        assertEquals("255.255.255.255/32", cidr("255.255.255.255/32").toString())
        assertEquals("10.0.0.0/8", cidr("10.1.2.3/8").toString())
        assertEquals(Range(0, 0xFFFFFFFFL), cidr("1.2.3.4/0").range)
    }

    @Test
    fun `should reject malformed cidrs`() {
        for (value in invalidCidrs)
            assertNull(Cidr.parse(value), value)
    }

    @Test
    fun `should merge adjacent nested and overlapping ranges`() {
        val ranges = cidrs(
            "10.0.1.0/24", "10.0.0.0/24", "10.0.0.128/25",
            "10.0.3.0/24", "10.0.2.128/25", "10.0.9.0/24",
        )
        val expected = listOf(
            Range(address("10.0.0.0"), address("10.0.1.255")),
            Range(address("10.0.2.128"), address("10.0.3.255")),
            cidr("10.0.9.0/24").range,
        )

        assertEquals(expected, merge(ranges.map { it.range }))
    }

    @Test
    fun `should cover range with minimal cidrs`() {
        val range = Range(address("10.0.0.1"), address("10.0.0.8"))

        assertEquals(cidrs("0.0.0.0/0"), cidr("0.0.0.0/0").range.cidrs)
        assertEquals(cidrs("1.2.3.4/32"), cidr("1.2.3.4/32").range.cidrs)
        assertEquals(cidrs("255.255.255.255/32"), cidr("255.255.255.255/32").range.cidrs)
        assertEquals(cidrs("128.0.0.0/1"), cidr("128.0.0.0/1").range.cidrs)
        assertEquals(cidrs("10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/30", "10.0.0.8/32"), range.cidrs)
    }

    @Test
    fun `should keep subnets fully inside geoip`() {
        val (clipped, report) = clip(cidrs("5.0.0.0/24", "5.0.1.0/24"), cidrs("5.0.0.0/16"))

        assertEquals(cidrs("5.0.0.0/23"), clipped)
        assertEquals(SubnetReport(dropped = 0, full = 2, topDropped = emptyList(), trimmed = 0), report)
    }

    @Test
    fun `should trim partially overlapping subnet`() {
        // like 7.64.0.0/12 upstream with only a sliver of it in Russia
        val geo = cidrs("7.70.1.0/24", "7.70.2.0/23", "7.79.255.255/32", "7.80.0.0/24")
        val (clipped, report) = clip(cidrs("7.64.0.0/12"), geo)

        assertEquals(cidrs("7.70.1.0/24", "7.70.2.0/23", "7.79.255.255/32"), clipped)
        assertEquals(1, report.trimmed)
    }

    @Test
    fun `should drop subnets outside geoip and report largest first`() {
        val whitelist = cidrs("1.0.0.0/24", "7.176.0.0/13", "8.0.0.0/16", "9.0.0.0/24", "9.0.0.0/24")
        val (clipped, report) = clip(whitelist, cidrs("1.0.0.0/8"))
        val topDropped = cidrs("7.176.0.0/13", "8.0.0.0/16", "9.0.0.0/24")

        assertEquals(cidrs("1.0.0.0/24"), clipped)
        assertEquals(SubnetReport(dropped = 3, full = 1, topDropped = topDropped, trimmed = 0), report)
    }

    @Test
    fun `should clip against whole internet`() {
        assertEquals(cidrs("1.2.3.0/24"), clip(cidrs("1.2.3.0/24"), cidrs("0.0.0.0/0")).first)
        assertEquals(cidrs("1.2.3.0/24"), clip(cidrs("0.0.0.0/0"), cidrs("1.2.3.0/24")).first)
        assertEquals(cidrs("0.0.0.0/0"), clip(cidrs("0.0.0.0/1", "128.0.0.0/1"), cidrs("0.0.0.0/0")).first)
    }

    @Test
    fun `should aggregate nested whitelist entries`() {
        val (clipped, report) = clip(cidrs("10.0.0.0/16", "10.0.5.0/24"), cidrs("10.0.0.0/8"))

        assertEquals(cidrs("10.0.0.0/16"), clipped)
        assertEquals(2, report.full)
    }

    private fun cidrs(vararg values: String): List<Cidr> =
        values.map(::cidr)

    private fun cidr(value: String): Cidr =
        Cidr.parse(value)!!

    private fun address(value: String): Long =
        cidr("$value/32").address

}
