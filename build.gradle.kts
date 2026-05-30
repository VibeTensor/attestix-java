import com.vanniktech.maven.publish.SonatypeHost
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent

plugins {
    `java-library`
    // Central Portal publishing (central.sonatype.com) + in-memory GPG signing.
    // Replaces the legacy OSSRH (s01.oss.sonatype.org) flow, which the new
    // Central Portal accounts do not use.
    id("com.vanniktech.maven.publish") version "0.30.0"
}

// Namespace VERIFIED on the Sonatype Central Portal (DNS TXT on vibetensor.com).
// Was io.vibetensor (a domain we do not own) — corrected to the verified one.
group = "com.vibetensor"
version = "0.4.0"
description = "Attestix offline credential verifier for Java — verify Ed25519 W3C VCs + UCAN delegations issued by the Attestix Python core."

java {
    // Library target is Java 11 for broad enterprise-JVM compatibility.
    // CI builds and tests on Temurin 17. (Sources + javadoc jars are added by
    // the maven-publish plugin's JavaLibrary platform — do not add them here too.)
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // BouncyCastle: trusted, deterministic Ed25519 (RFC 8032) implementation.
    api("org.bouncycastle:bcprov-jdk18on:1.78.1")

    testImplementation(platform("org.junit:junit-bom:5.10.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(11)
    options.encoding = "UTF-8"
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events(TestLogEvent.PASSED, TestLogEvent.FAILED, TestLogEvent.SKIPPED)
        exceptionFormat = TestExceptionFormat.FULL
        showStandardStreams = true
    }
}

// --- Maven Central (Central Portal) publishing ------------------------------
// Credentials + GPG key are supplied ONLY at release time via env vars (set as
// encrypted GitHub Actions secrets, never committed). The vanniktech plugin
// reads the ORG_GRADLE_PROJECT_* names:
//   ORG_GRADLE_PROJECT_mavenCentralUsername       -> Central Portal token user
//   ORG_GRADLE_PROJECT_mavenCentralPassword       -> Central Portal token pass
//   ORG_GRADLE_PROJECT_signingInMemoryKey         -> ASCII-armored GPG private key
//   ORG_GRADLE_PROJECT_signingInMemoryKeyPassword -> GPG passphrase
mavenPublishing {
    // automaticRelease=true publishes straight through after Central validation
    // (no manual "release" button in the portal). Flip to false to stage first.
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL, automaticRelease = true)
    signAllPublications()

    coordinates("com.vibetensor", "attestix", version.toString())

    pom {
        name.set("Attestix Java Verifier")
        description.set(project.description)
        url.set("https://github.com/VibeTensor/attestix-java")
        licenses {
            license {
                name.set("Apache License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
                id.set("vibetensor")
                name.set("VibeTensor")
                url.set("https://attestix.io")
            }
        }
        scm {
            connection.set("scm:git:https://github.com/VibeTensor/attestix-java.git")
            developerConnection.set("scm:git:ssh://git@github.com/VibeTensor/attestix-java.git")
            url.set("https://github.com/VibeTensor/attestix-java")
        }
    }
}
