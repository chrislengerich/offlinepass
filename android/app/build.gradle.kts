plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.linuxpass.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.linuxpass.app"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0-spike"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
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
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }

    testOptions {
        unitTests {
            // Robolectric can only inflate resources if the merged resources
            // travel with the unit tests (offlinecam pattern).
            isIncludeAndroidResources = true
        }
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

    // S2 spike: standalone SSH client for the Keystore-identity auth test
    // (maintained jsch fork; supports ed25519 + rsa-sha2-256).
    implementation("com.github.mwiede:jsch:0.2.17")

    // Testing (offlinecam pattern)
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.11.1")
    testImplementation("org.mockito:mockito-core:5.8.0")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.2.1")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:$coroutinesVersion")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}
