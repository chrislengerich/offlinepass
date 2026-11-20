plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.offlinepass.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.offlinepass.app"
        minSdk = 26
        targetSdk = 34
        versionCode = 7
        versionName = "0.10.4"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        // Release-grade build (minified, not debuggable) with the <profileable>
        // manifest tag (src/profileable/): profilers can attach without the
        // app being debuggable. Ships unsigned; signed in scripts/release.sh.
        create("profileable") {
            initWith(getByName("release"))
            matchingFallbacks += listOf("release")
            applicationIdSuffix = ".profileable"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        // The vendored OpenPGP API talks to OpenKeychain through its AIDL
        // interface (IOpenPgpService2), which needs AIDL compilation on.
        aidl = true
    }
    composeOptions {
        // Matches Kotlin 1.9.22.
        kotlinCompilerExtensionVersion = "1.5.8"
    }

    packaging {
        resources.excludes += setOf(
            "META-INF/**",
        )
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
        resources.excludes += "/META-INF/versions/9/OSGI-INF/MANIFEST.MF"
    }

    testOptions {
        unitTests {
            // Robolectric can only inflate resources if the merged resources
            // travel with the unit tests (offlinecam pattern).
            isIncludeAndroidResources = true
            // android.util.Log calls inside the crypto classes (the
            // YubiKeySsh diagnostics) are no-ops in plain unit tests.
            isReturnDefaultValues = true
            all {
                it.testLogging {
                    events("failed")
                    setShowStandardStreams(true)
                }
                it.systemProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug")
                it.systemProperty("org.slf4j.simpleLogger.showThreadName", "false")
            }
        }
    }

    lint {
        // The app uses no Fragments — activity results go through
        // activity-compose on ComponentActivity, so the "upgrade fragment"
        // check (225 hits, fires on every ActivityResult contract use)
        // doesn't apply.
        disable += "InvalidFragmentVersionForActivityResult"
    }
}

dependencies {
    val lifecycleVersion = "2.7.0"
    val coroutinesVersion = "1.7.3"

    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:$lifecycleVersion")

    // Compose UI
    implementation(platform("androidx.compose:compose-bom:2024.02.01"))
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:$coroutinesVersion")

    // Biometric gate (unlock flow)
    implementation("androidx.biometric:biometric:1.1.0")

    // Git transport. HTTPS-only in offlinecam (proven); the SSH transport
    // (org.eclipse.jgit.ssh.apache + OpenKeyChain-backed auth) lands with
    // the S2/S3 spikes.
    implementation("org.eclipse.jgit:org.eclipse.jgit:7.7.1.202607240634-r")
    implementation("org.slf4j:slf4j-nop:2.0.18")

    // QR rendering for single-entry exports
    implementation("com.google.zxing:core:3.5.3")

    // WebView asset loader (serves the vendored qrft generator at a secure origin)
    implementation("androidx.webkit:webkit:1.9.0")

    // S2 spike: standalone SSH client for the Keystore-identity auth test
    // BouncyCastle: the OpenPGP framing for the YubiKit decrypt path
    // (the PublicKeyDataDecryptorFactory-style seam — the card recovers
    // the session key, BC owns the CFB/MDC/literal).
    implementation("org.bouncycastle:bcprov-jdk18on:1.87")
    implementation("com.github.mwiede:jsch:0.2.17")
    // Direct OpenPGP-applet access (the card's AUTH slot) — the SSH auth
    // backend for card-resident keys; OpenKeyChain's remote API returns
    // UNSUPPORTED_ACTION for card signing. 3.3.0: the smartcard transport
    // rewrite — ExtendedApduProcessor (the extended APDU with the command-
    // chaining fallback) replaces 3.0.0's raw extended send; the RSA-4096
    // DEC slot's 512-byte PSO:DEC rides it.
    // MIXED 3.3.0/3.0.0: the core 3.3.0 = the transport rewrite
    // (ExtendedApduProcessor — the extended APDU with the chaining
    // fallback) and is PURE JAVA; the openpgp 3.3.0 = pure Java too.
    // The android artifact 3.3.0 = the only Kotlin-2.2-compiled one
    // (unreadable by our Kotlin 1.9.22 toolchain) — the 3.0.0 android =
    // Kotlin-1.9 and binary-compatible (the SmartCardConnection
    // interface = byte-identical across the versions, verified).
    implementation("com.yubico.yubikit:openpgp:3.3.0")
    implementation("com.yubico.yubikit:android:3.0.0")

    // Testing (offlinecam pattern)
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.11.1")
    testImplementation("org.mockito:mockito-core:5.8.0")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.2.1")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:$coroutinesVersion")
    // A real local SSH server for the no-network handshake tests (JVM only —
    // never packaged). slf4j-simple surfaces the server's auth decisions.
    testImplementation("org.apache.sshd:sshd-core:2.12.1")
    testImplementation("org.slf4j:slf4j-simple:2.0.13")
    // The OpenPGP framing for the card decrypt + the envelope encrypt
    // (the SEIPD CFB, the MDC, the literal/compressed, the PKESKs) via
    // the PublicKeyDataDecryptorFactory seam — the card recovers the
    // session key, BC does everything else.
    implementation("org.bouncycastle:bcpg-jdk18on:1.87")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}
