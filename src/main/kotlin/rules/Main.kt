package rules

import com.github.ajalt.clikt.core.CliktError
import com.github.ajalt.clikt.core.CoreCliktCommand
import com.github.ajalt.clikt.core.context
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.path
import java.net.HttpURLConnection.HTTP_OK
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Path
import java.time.Instant
import java.util.Properties
import kotlin.io.path.*
import kotlin.system.exitProcess

private const val DOMAIN_MRS = "ru-whitelist-domain.mrs"
private const val DOMAIN_TXT = "ru-whitelist-domain.txt"
private const val GEOIP_BRANCH = "meta"
private const val GEOIP_PATH = "geo/geoip/ru.list"
private const val GEOIP_REPO = "MetaCubeX/meta-rules-dat"
private const val GITHUB_API = "https://api.github.com/"
private const val IPCIDR_MRS = "ru-whitelist-ipcidr.mrs"
private const val IPCIDR_TXT = "ru-whitelist-ipcidr.txt"
private const val WHITELIST_BRANCH = "main"
private const val WHITELIST_REPO = "hxehex/russia-mobile-internet-whitelist"

private const val MAX_LOGGED_INVALID = 20

private val SHA_REGEX = Regex("[0-9a-f]{40}")

fun main(args: Array<String>) {
    BuildCommand().main(args)
}

/** Builds the rule-sets from the current upstream heads. */
class BuildCommand : CoreCliktCommand(name = "ru-whitelist-rules") {

    private val allowSizeChange by option(help = "Skip the size gate").flag()
    private val mihomo by option(help = "mihomo binary; without it the .mrs files are skipped").path(mustExist = true)
    private val out by option(help = "Output directory").path().required()
    private val prev by option(help = "Last published release, for the size gate").path(mustExist = true)

    // clikt-core neither exits with the error status nor writes to stderr unless told to
    init {
        context {
            exitProcess = ::exitProcess
            echoMessage = { _, message, newline, err ->
                val stream = if (err) System.err else System.out
                if (newline) stream.println(message) else stream.print(message)
            }
        }
    }

    override fun run() {
        val previous = prev?.let(::readPrevious)
        val config = Properties().apply { Path("config/build.properties").reader().use(::load) }
        val denylist = Denylist(Path("config/denylist.txt").readLines())

        val whitelistSha = fetchHeadSha(WHITELIST_REPO, WHITELIST_BRANCH)
        val geoipSha = fetchHeadSha(GEOIP_REPO, GEOIP_BRANCH)
        echo("$WHITELIST_REPO@$whitelistSha\n$GEOIP_REPO@$geoipSha")

        val inputs = Inputs(
            cidrs = fetchRaw(WHITELIST_REPO, whitelistSha, "cidrwhitelist.txt").lines(),
            domains = fetchRaw(WHITELIST_REPO, whitelistSha, "whitelist.txt").lines(),
            geoip = fetchRaw(GEOIP_REPO, geoipSha, GEOIP_PATH).lines(),
        )

        val maxChangePercent = config.getProperty("maxSizeChangePercent").toInt()

        val result = try {
            build(inputs, denylist, previous, maxChangePercent, allowSizeChange)
        } catch (e: GateFailure) {
            throw CliktError("Sanity gate failed, nothing will be published:\n${e.message}")
        }

        out.createDirectories()
        (out / DOMAIN_TXT).writeLines(result.domains)
        (out / IPCIDR_TXT).writeLines(result.cidrs.map { it.toString() })
        (out / "LICENSE-upstream").writeText(fetchRaw(WHITELIST_REPO, whitelistSha, "LICENSE"))

        val mihomoVersion = mihomo?.let { convertRuleSets(it, out) }
        val meta = composeMeta(result, whitelistSha, geoipSha, mihomoVersion)
        (out / "meta.json").writeText(meta)
        echo(meta)

        if (result.invalidDomains.isNotEmpty())
            echo("Invalid domains: ${result.invalidDomains.take(MAX_LOGGED_INVALID)}")

        if (result.invalidCidrs.isNotEmpty())
            echo("Invalid subnets: ${result.invalidCidrs.take(MAX_LOGGED_INVALID)}")

        if (mihomo == null) {
            echo("No --mihomo given, .mrs files skipped")
        }
    }

}

private fun readPrevious(dir: Path): Previous? {
    val cidrs = countLines(dir / IPCIDR_TXT)
    val domains = countLines(dir / DOMAIN_TXT)
    return if (cidrs != null && domains != null) Previous(cidrs, domains) else null
}

private fun fetchHeadSha(repo: String, branch: String): String {
    val sha = fetchText("${GITHUB_API}repos/$repo/commits/$branch", accept = "application/vnd.github.sha").trim()
    check(SHA_REGEX.matches(sha)) { "Unexpected SHA for $repo@$branch: $sha" }
    return sha
}

private fun fetchRaw(repo: String, sha: String, path: String): String =
    fetchText("https://raw.githubusercontent.com/$repo/$sha/$path")

private fun fetchText(url: String, accept: String? = null): String {
    val token = System.getenv("GITHUB_TOKEN")?.takeIf { url.startsWith(GITHUB_API) }

    val request = HttpRequest.newBuilder(URI(url)).apply {
        accept?.let { header("Accept", it) }
        token?.let { header("Authorization", "Bearer $it") }
    }.build()

    val response = http.send(request, HttpResponse.BodyHandlers.ofString())
    check(response.statusCode() == HTTP_OK) { "GET $url -> HTTP ${response.statusCode()}" }
    return response.body()
}

private fun convertRuleSets(mihomo: Path, out: Path): String {
    convertRuleSet(mihomo, "domain", out / DOMAIN_TXT, out / DOMAIN_MRS)
    convertRuleSet(mihomo, "ipcidr", out / IPCIDR_TXT, out / IPCIDR_MRS)
    return runCommand("$mihomo", "-v").lines().first().trim()
}

private fun convertRuleSet(mihomo: Path, behavior: String, source: Path, target: Path) {
    runCommand("$mihomo", "convert-ruleset", behavior, "text", "$source", "$target")
}

private fun runCommand(vararg command: String): String {
    val process = ProcessBuilder(*command).redirectErrorStream(true).start()
    val output = process.inputStream.bufferedReader().readText()
    check(process.waitFor() == 0) { "${command.joinToString(" ")} failed:\n$output" }
    return output
}

private fun composeMeta(result: BuildResult, whitelistSha: String, geoipSha: String, mihomoVersion: String?): String {
    val subnets = result.subnets
    return """
        |{
        |  "builtAt": ${quoteJson(Instant.now().toString())},
        |  "mihomo": ${quoteJson(mihomoVersion ?: "not used")},
        |  "upstreams": {
        |    ${quoteJson(WHITELIST_REPO)}: ${quoteJson(whitelistSha)},
        |    ${quoteJson(GEOIP_REPO)}: ${quoteJson(geoipSha)}
        |  },
        |  "domains": {
        |    "output": ${result.domains.size},
        |    "invalid": ${result.invalidDomains.size}
        |  },
        |  "ipcidr": {
        |    "output": ${result.cidrs.size},
        |    "invalid": ${result.invalidCidrs.size},
        |    "full": ${subnets.full},
        |    "trimmed": ${subnets.trimmed},
        |    "dropped": ${subnets.dropped},
        |    "topDropped": [${subnets.topDropped.joinToString { quoteJson(it.toString()) }}]
        |  }
        |}
        |""".trimMargin()
}

private fun countLines(file: Path): Int? =
    if (file.exists()) file.readLines().count { it.isNotBlank() } else null

private fun quoteJson(value: String): String =
    "\"${value.replace("\\", "\\\\").replace("\"", "\\\"")}\""

private val http = HttpClient.newBuilder()
    .followRedirects(HttpClient.Redirect.NORMAL)
    .build()
