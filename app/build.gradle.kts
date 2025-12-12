plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.example.app1"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.app1"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
        ndkVersion = "28.0.12433566"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        externalNativeBuild {

        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    buildFeatures {
        prefab = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    externalNativeBuild {

    }




}

task("testClasses")

dependencies {
    implementation(libs.appcompat)
    implementation(libs.material)
    implementation(libs.activity)
    implementation(libs.constraintlayout)
    testImplementation(libs.junit)
    androidTestImplementation(libs.ext.junit)
    androidTestImplementation(libs.espresso.core)
    implementation (libs.guava)
    implementation (libs.cbor)
    implementation (libs.dev.core.ktx)

    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar"))))

    //noinspection GradleDependency
    implementation (libs.okhttp)
    implementation ("org.bouncycastle:bcprov-jdk18on:1.76")
    implementation (libs.xposeddetector)

}