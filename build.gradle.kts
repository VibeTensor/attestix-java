import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent

plugins {
    `java-library`
    `maven-publish`
    signing
}

group = "io.vibetensor"
version = "0.4.0"
description = "Attestix offline credential verifier for Java — verify Ed25519 W3C VCs + UCAN delegations."

java {
    // Library target is Java 11 for broad enterprise-JVM compatibility.
    // CI builds and tests on Temurin 17.
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
    withSourcesJar()
    withJavadocJar()
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

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            artifactId = "attestix"
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
    }
    repositories {
        maven {
            // Sonatype OSSRH / Central Portal staging. Credentials + GPG signing
            // supplied via env/Gradle props at publish time (NOT committed).
            name = "ossrh"
            val releasesUrl = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            val snapshotsUrl = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
            url = if (version.toString().endsWith("SNAPSHOT")) snapshotsUrl else releasesUrl
            credentials {
                username = (project.findProperty("ossrhUsername") as String?) ?: System.getenv("OSSRH_USERNAME")
                password = (project.findProperty("ossrhPassword") as String?) ?: System.getenv("OSSRH_PASSWORD")
            }
        }
    }
}

signing {
    // Only sign when a signing key is configured (e.g. release publish). No-op in CI test.
    isRequired = gradle.taskGraph.hasTask("publish")
    val signingKey: String? = System.getenv("SIGNING_KEY")
    val signingPassword: String? = System.getenv("SIGNING_PASSWORD")
    if (signingKey != null) {
        useInMemoryPgpKeys(signingKey, signingPassword)
    }
    sign(publishing.publications["mavenJava"])
}
