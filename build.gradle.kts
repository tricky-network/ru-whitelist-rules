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
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}
