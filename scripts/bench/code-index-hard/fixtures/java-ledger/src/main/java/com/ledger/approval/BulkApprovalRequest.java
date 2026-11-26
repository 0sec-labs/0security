package com.ledger.approval;

import java.util.List;

public record BulkApprovalRequest(String approverId, List<String> ids) {
}
