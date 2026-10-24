package rules

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

internal class BuildTest {

    private val denylist = Denylist(listOf("ru", "+.google.com"))
    private val inputs = Inputs(
        cidrs = listOf("5.0.0.0/24", "5.0.1.0/24", "7.64.0.0/12", "8.8.8.0/24", "2a00::/32", ""),
        domains = listOf("vk.ru", "VK.ru", "", "ya.ru", "bad_host.ru", "ДОМЕН.РФ"),
        geoip = listOf("5.0.0.0/16", "7.70.0.0/16", "2a00::/16"),
    )

    @Test
    fun `should normalize domains and clip subnets`() {
        val result = runBuild()
        val report = SubnetReport(
            dropped = 1,
            full = 2,
            topDropped = listOf(Cidr.parse("8.8.8.0/24")!!),
            trimmed = 1,
        )

        assertEquals(listOf("vk.ru", "xn--d1acufc.xn--p1ai", "ya.ru"), result.domains)
        assertEquals(listOf("bad_host.ru"), result.invalidDomains)
        assertEquals(listOf("5.0.0.0/23", "7.70.0.0/16"), result.cidrs.map { it.toString() })
        assertEquals(listOf("2a00::/32"), result.invalidCidrs)
        assertEquals(report, result.subnets)
    }

    @Test
    fun `should fail when denylist is hit`() {
        val domains = inputs.domains + "mail.google.com" + "ru"
        val failure = assertFailsWith<GateFailure> { runBuild(inputs.copy(domains = domains)) }
        val message = failure.message.orEmpty()

        assertTrue("mail.google.com" in message && ", ru" in message, message)
    }

    @Test
    fun `should fail when any list is empty`() {
        assertFailsWith<GateFailure> { runBuild(inputs.copy(domains = listOf("", "bad_host"))) }
        assertFailsWith<GateFailure> { runBuild(inputs.copy(cidrs = emptyList())) }
        // nothing survives the geoip clip
        assertFailsWith<GateFailure> { runBuild(inputs.copy(geoip = listOf("100.0.0.0/8"))) }
    }

    @Test
    fun `should fail when size changes beyond limit`() {
        // 2 subnets and 3 domains now
        runBuild(previous = Previous(cidrs = 2, domains = 3))
        runBuild(previous = Previous(cidrs = 2, domains = 4)) // -25%
        runBuild(previous = Previous(cidrs = 0, domains = 0)) // nothing to compare with
        assertFailsWith<GateFailure> { runBuild(previous = Previous(cidrs = 2, domains = 5)) } // -40%
        assertFailsWith<GateFailure> { runBuild(previous = Previous(cidrs = 1, domains = 3)) } // +100%
        runBuild(previous = Previous(cidrs = 1, domains = 100), allowSizeChange = true)
    }

    private fun runBuild(
        inputs: Inputs = this.inputs,
        previous: Previous? = null,
        allowSizeChange: Boolean = false,
    ): BuildResult =
        build(inputs, denylist, previous, maxChangePercent = 30, allowSizeChange)

}
