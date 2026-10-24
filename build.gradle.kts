plugins {
    kotlin("jvm") version "2.4.21"
    application
}

application {
    mainClass = "rules.MainKt"
}

kotlin {
    jvmToolchain(25)
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.github.ajalt.clikt:clikt-core:5.1.0")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}
