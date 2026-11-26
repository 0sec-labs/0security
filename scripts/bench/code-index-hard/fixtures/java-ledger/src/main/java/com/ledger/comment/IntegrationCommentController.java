package com.ledger.comment;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Receives comments relayed from the mail and chat integrations. Restricted to the service role by the URL rules.
 */
@RestController
@RequestMapping("/api/integrations/comments")
public class IntegrationCommentController {

    private final CommentService service;

    public IntegrationCommentController(CommentService service) {
        this.service = service;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Comment relay(@RequestBody CommentInput input) {
        return service.add(input);
    }
}
