package com.ledger.common;

import java.util.regex.Pattern;

public final class Text {

    private static final Pattern TAGS = Pattern.compile("<[^>]*>");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");
    private static final Pattern SEGMENT_INVALID = Pattern.compile("[^A-Za-z0-9._-]");

    private Text() {
    }

    /**
     * Strips markup so the value can be rendered in an HTML page.
     */
    public static String plain(String raw) {
        if (raw == null) {
            return "";
        }
        String stripped = TAGS.matcher(raw).replaceAll("");
        stripped = stripped.replace("<", "").replace(">", "");
        return WHITESPACE.matcher(stripped).replaceAll(" ").strip();
    }

    /**
     * Reduces a client supplied name to one file name component: no separators, no dot sequences.
     */
    public static String safeSegment(String raw) {
        String cleaned = SEGMENT_INVALID.matcher(raw == null ? "" : raw).replaceAll("_");
        while (cleaned.contains("..")) {
            cleaned = cleaned.replace("..", "_");
        }
        while (cleaned.startsWith(".")) {
            cleaned = cleaned.substring(1);
        }
        if (cleaned.length() > 80) {
            cleaned = cleaned.substring(0, 80);
        }
        return cleaned.isEmpty() ? "unnamed" : cleaned;
    }

    public static String required(String value, String field) {
        String cleaned = plain(value);
        if (cleaned.isEmpty()) {
            throw new BadRequestException(field + " is required");
        }
        return cleaned;
    }
}
