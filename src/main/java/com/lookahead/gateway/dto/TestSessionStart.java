package com.lookahead.gateway.dto;

/** What the browser sends to start a DEV test session: the id of the test account to use. */
public record TestSessionStart(String accountId) {}
