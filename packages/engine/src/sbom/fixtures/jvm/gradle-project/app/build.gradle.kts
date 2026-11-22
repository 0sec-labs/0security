plugins { kotlin("jvm") }

dependencies {
    implementation(libs.jackson.databind)
    implementation("org.apache.commons:commons-lang3:3.14.0")
    implementation("org.slf4j:slf4j-api:2.0.99") // locked to 2.0.9, so the lockfile wins
    testImplementation("org.mockito:mockito-core:5.8.0")
    // implementation("com.commented:out:1.0")
}
