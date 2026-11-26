package com.example.shop

import io.ktor.server.application.Application
import io.ktor.server.auth.authenticate
import io.ktor.server.routing.get
import io.ktor.server.routing.routing

class HealthChecker(private val audit: AuditLog) {
    fun status(): String {
        audit.record("status")
        return "ok"
    }
}

fun Application.module(checker: HealthChecker) {
    routing {
        get("/kt/health") { call.respondText(checker.status()) }
        authenticate("jwt") {
            get("/kt/me") { call.respondText(java.io.File("/etc/motd").readText()) }
        }
    }
}
