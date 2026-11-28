package com.ledger.config;

import java.nio.file.Path;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "ledger")
public record LedgerProperties(String tokenSecret, String exportDir, String templateDir, boolean demoData) {

    public Path exportPath() {
        return Path.of(exportDir == null || exportDir.isBlank() ? "data/exports" : exportDir);
    }

    public Path templatePath() {
        return Path.of(templateDir == null || templateDir.isBlank() ? "data/templates" : templateDir);
    }
}
