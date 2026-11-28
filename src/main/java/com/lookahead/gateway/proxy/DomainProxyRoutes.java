package com.lookahead.gateway.proxy;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Set;

/**
 * The allow-list of Domain routes the Gateway BFF relays: one predicate per group of routes, each
 * matching method and exact path.
 */
public final class DomainProxyRoutes {
  private DomainProxyRoutes() {}

  /**
   * What the relay needs to know about one request, in the order it asks: the Domain path, whether
   * the method is refused (405), whether the route is not on the allow-list (404), whether a DEV
   * test session is refused (401), whether only a staff sign-in or a test session may call (401),
   * how many body bytes are read (413 above that), and whether it is an execution route (which has
   * its own answer limit).
   */
  record Match(
      String upstreamPath,
      boolean methodRefused,
      boolean unknown,
      boolean testSessionRefused,
      boolean staffOnly,
      int bodyLimit,
      boolean execution) {}

  /** DLV-928: platform review uploads carry up to six 5 MB images (20 MB) plus the item text. */
  public static final int PLATFORM_REVIEW_BODY_BYTES = 21 * 1024 * 1024;

  /**
   * Classifies one browser request against the allow-lists below; nothing is read from it but
   * method, path and query string.
   */
  static Match match(HttpServletRequest request) {
    String route = request.getRequestURI();
    String upstreamPath = route.startsWith("/bff/") ? route.substring(4) : route;
    boolean content = upstreamPath.startsWith("/content/") && request.getMethod().equals("GET");
    boolean account =
        upstreamPath.equals("/api/v1/auth/me")
            || upstreamPath.equals("/api/v1/account-catalog")
            || upstreamPath.equals("/api/v1/support")
            || upstreamPath.equals("/api/v1/plans")
            || upstreamPath.startsWith("/api/v1/plans/");
    boolean staffAccess =
        ("GET".equals(request.getMethod())
                    && Set.of(
                            "/api/v1/account/permissions",
                            "/api/v1/admin/access",
                            "/api/v1/admin/access/catalog",
                            "/api/v1/admin/access/waiting")
                        .contains(upstreamPath)
                || "POST".equals(request.getMethod())
                    && Set.of(
                            "/api/v1/admin/access",
                            "/api/v1/admin/access/lookup",
                            "/api/v1/admin/access/admit",
                            "/api/v1/auth/invitations/activate")
                        .contains(upstreamPath))
            && request.getQueryString() == null;
    boolean directory =
        "GET".equals(request.getMethod()) && "/api/v1/admin/accounts".equals(upstreamPath);
    boolean membership =
        membershipRoute(request.getMethod(), upstreamPath) && request.getQueryString() == null;
    boolean execution =
        executionRoute(request.getMethod(), upstreamPath) && request.getQueryString() == null;
    boolean authorReview =
        authorReviewRoute(request.getMethod(), upstreamPath)
            && (!"POST".equals(request.getMethod()) || request.getQueryString() == null);
    boolean platformReview =
        platformReviewRoute(request.getMethod(), upstreamPath)
            && ("GET".equals(request.getMethod()) || request.getQueryString() == null);
    // DLV-971: the delivery plan follows the platform-review rules (query string on GET only).
    boolean delivery =
        deliveryRoute(request.getMethod(), upstreamPath)
            && ("GET".equals(request.getMethod()) || request.getQueryString() == null);
    // DLV-971: the owner's "run the 4-hour jobs now"; no query string, no body to speak of.
    boolean sweeps =
        sweepsRoute(request.getMethod(), upstreamPath) && request.getQueryString() == null;
    // PUT exists only for platform reviews and delivery work items; every other route keeps its
    // earlier methods.
    boolean methodRefused = "PUT".equals(request.getMethod()) && !platformReview && !delivery;
    boolean unknown =
        !content
            && !account
            && !execution
            && !authorReview
            && !platformReview
            && !delivery
            && !sweeps
            && !staffAccess
            && !membership
            && !directory;
    // DLV-971: the delivery plan, promoting a review onto it and running the sweeps are staff work;
    // a test session is refused there.
    boolean testSessionRefused =
        (delivery || sweeps || promoteRoute(request.getMethod(), upstreamPath));
    boolean staffOnly =
        (directory
            || authorReview
            || platformReview
            || delivery
            || sweeps
            || staffAccess
            || membership
                && !Set.of("/api/v1/membership/plans", "/api/v1/sales/active")
                    .contains(upstreamPath));
    int bodyLimit =
        (authorReview || staffAccess || sweeps)
            ? 16 * 1024
            : execution
                ? 512 * 1024
                : platformReview ? PLATFORM_REVIEW_BODY_BYTES : 8 * 1024 * 1024;
    return new Match(
        upstreamPath, methodRefused, unknown, testSessionRefused, staffOnly, bodyLimit, execution);
  }

  static boolean authorReviewRoute(String method, String path) {
    return "GET".equals(method) && "/api/v1/author/review-artifacts".equals(path)
        || ("GET".equals(method) || "POST".equals(method))
            && path.matches("/api/v1/author/review-artifacts/[a-z0-9][a-z0-9-]{0,79}/events");
  }

  private static final String UUID_ID =
      "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

  /**
   * A platform-review item id: the UUIDs of the day-file records, or the numbered ids of the
   * runtime record stores (REV-000001 for feedback, SUP-000001 for a learner support ticket;
   * DLV-971, owner 2026-11-06). Attachment ids stay UUIDs.
   */
  private static final String PLATFORM_REVIEW_ID = "(?:" + UUID_ID + "|(?:REV|SUP)-[0-9]{6,})";

  private static final String PLATFORM_REVIEWS = "/api/v1/platform-reviews",
      PLATFORM_REVIEW = PLATFORM_REVIEWS + "/" + PLATFORM_REVIEW_ID;

  static boolean platformReviewRoute(String method, String path) {
    String root = PLATFORM_REVIEWS, item = PLATFORM_REVIEW;
    return switch (method) {
      case "GET" ->
          path.equals(root)
              || path.equals(root + "/me")
              || path.matches(item)
              || path.matches(item + "/attachments/" + UUID_ID);
      case "POST" -> path.equals(root) || promoteRoute(method, path);
      case "PUT" -> path.matches(item) || path.matches(item + "/triage");
      case "DELETE" -> path.matches(item);
      default -> false;
    };
  }

  /**
   * DLV-971: promoting a platform review onto the delivery plan; one of the platform-review routes,
   * staff sign-ins only.
   */
  static boolean promoteRoute(String method, String path) {
    return "POST".equals(method) && path.matches(PLATFORM_REVIEW + "/promote");
  }

  /**
   * DLV-971: the owner's "Run the 4-hour jobs now" (Domain decides it is the owner); staff sign-ins
   * only, like the delivery plan.
   */
  static boolean sweepsRoute(String method, String path) {
    return "POST".equals(method) && "/api/v1/sweeps/run".equals(path);
  }

  /**
   * DLV-971: the delivery plan. A work item id is a letter or digit followed by up to 79 letters,
   * digits, dots, underscores or hyphens.
   */
  private static final String DELIVERY_PLAN = "/api/v1/delivery/plan",
      WORK_ITEM = DELIVERY_PLAN + "/work-items/[A-Za-z0-9][A-Za-z0-9._-]{0,79}";

  static boolean deliveryRoute(String method, String path) {
    return switch (method) {
      case "GET" -> path.equals(DELIVERY_PLAN);
      // DLV-971 (owner, 2026-11-07): the Delivery Plan page's Upload plan file (the file as the
      // body) and Sync plan inbox.
      case "POST" ->
          path.equals(DELIVERY_PLAN + "/work-items")
              || path.matches(WORK_ITEM + "/resolve-conflict")
              || path.equals(DELIVERY_PLAN + "/inbox/sync");
      case "PUT" -> path.matches(WORK_ITEM) || path.equals(DELIVERY_PLAN + "/inbox");
      default -> false;
    };
  }

  static boolean membershipRoute(String method, String path) {
    return switch (method) {
      case "GET" ->
          Set.of(
                      "/api/v1/membership/plans",
                      "/api/v1/sales/active",
                      "/api/v1/account/access-records",
                      "/api/v1/account/access-summary",
                      "/api/v1/admin/test-accounts",
                      "/api/v1/admin/test-accounts/allowance")
                  .contains(path)
              || path.matches("/api/v1/account/purchases/" + UUID_ID)
              || path.matches(
                  "/api/v1/admin/accounts/" + UUID_ID + "/(access-records|access-summary)");
      case "POST" ->
          Set.of(
                      "/api/v1/account/purchases",
                      "/api/v1/account/purchases/quote",
                      "/api/v1/admin/sales",
                      "/api/v1/admin/test-accounts")
                  .contains(path)
              || path.matches("/api/v1/admin/test-accounts/" + UUID_ID + "/reset")
              || path.matches(
                  "/api/v1/admin/accounts/"
                      + UUID_ID
                      + "/(plan-upgrades|downgrade|delete|disable|enable|remove)")
              || path.matches("/api/v1/admin/sales/" + UUID_ID + "/stop")
              || path.matches("/api/v1/admin/membership/plans/[a-z-]{1,40}/price");
      case "DELETE" -> path.matches("/api/v1/admin/test-accounts/" + UUID_ID);
      default -> false;
    };
  }

  static boolean executionRoute(String method, String path) {
    return "GET".equals(method) && "/api/v1/executions/capabilities".equals(path)
        || "POST".equals(method) && "/api/v1/executions/jobs".equals(path)
        || ("GET".equals(method) || "DELETE".equals(method))
            && path.matches(
                "/api/v1/executions/jobs/[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}");
  }
}
