package rules

import kotlin.io.path.Path
import kotlin.io.path.readLines
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

internal class DomainsTest {

    private val invalidDomains = listOf(
        "", "   ", "*.vk.ru", "+.vk.ru", "vk..ru", ".vk.ru", "-a.ru", "a-.ru", "a_b.ru", "vk.ru/path",
        "http://vk.ru", "1.2.3.4/24 ", "a b.ru", "xn--.ru", "xn--zz-zzzz.ru", "${"a".repeat(64)}.ru",
        "${"a.".repeat(127)}ru",
    )

    @Test
    fun `should normalize case whitespace trailing dot and idn`() {
        assertEquals("api.vk.ru", normalizeDomain("  API.VK.ru  "))
        assertEquals("ya.ru", normalizeDomain("ya.ru."))
        assertEquals("xn--d1acufc.xn--p1ai", normalizeDomain("ДОМЕН.РФ"))
        assertEquals("xn--d1acufc.xn--p1ai", normalizeDomain("xn--d1acufc.xn--p1ai"))
        assertEquals("a-b.example.com", normalizeDomain("a-b.example.com"))
    }

    @Test
    fun `should reject invalid domains`() {
        for (value in invalidDomains)
            assertNull(normalizeDomain(value), value)
    }

    @Test
    fun `should match exact and wildcard denylist entries`() {
        val denylist = Denylist(listOf("# comment", "com", "", "+.google.com  # inline", "+.example.org"))

        assertTrue(denylist.matches("com"))
        assertFalse(denylist.matches("vk.com"))
        assertTrue(denylist.matches("google.com"))
        assertTrue(denylist.matches("www.google.com"))
        assertFalse(denylist.matches("notgoogle.com"))
        assertTrue(denylist.matches("a.b.example.org"))
    }

    @Test
    fun `should parse shipped denylist`() {
        Denylist(Path("config/denylist.txt").readLines())
    }

}
