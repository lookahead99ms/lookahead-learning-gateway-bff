package com.lookahead.gateway.util;

import jakarta.servlet.http.HttpServletRequest;
import tools.jackson.databind.JsonNode;

/**
 * DLV-969 S36: the account-merge offer after sign-in: the two attribute names and the checks around
 * them.
 */
public final class AccountMergeOffer {
  private AccountMergeOffer() {}

  /**
   * DLV-969 S36: request attribute set when Domain admitted the sign-in and answered {@code
   * mergeAvailable: true}.
   */
  public static final String MERGE_AVAILABLE = "lookaheadMergeAvailable";

  /**
   * DLV-969 S36: session attribute set when a resolved sign-in challenge answered {@code
   * mergeAvailable: true}; used once by /bff/login.
   */
  public static final String MERGE_AFTER_CHALLENGE = "lookaheadMergeAfterChallenge";

  /**
   * True only after this request's sign-in was admitted with a literal {@code mergeAvailable: true}
   * (DLV-969 S36).
   */
  public static boolean mergeAvailable(HttpServletRequest request) {
    return Boolean.TRUE.equals(request.getAttribute(MERGE_AVAILABLE));
  }

  /**
   * DLV-969 S36: only a JSON boolean {@code true} counts; a string, number or missing field never
   * does.
   */
  public static boolean literalTrue(JsonNode value) {
    return value != null && value.isBoolean() && value.booleanValue();
  }

  /**
   * DLV-969 S36: a redirect sign-in cannot show the inbox panel, so the merge page offers the
   * email. A merge target that already has its query (safeReturn allows only the email token and/or
   * offer=1) stays; a bare /account/merge gets the offer.
   */
  public static String mergeOffer(String next) {
    if (next.startsWith("/account/merge?")) return next;
    return "/account/merge?offer=1";
  }
}
