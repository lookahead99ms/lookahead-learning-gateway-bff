package com.lookahead.gateway.proxy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * DLV-1015: the classification of one request (moved here from DomainProxyController.proxy,
 * statements unchanged); the answers built from it are driven in DomainProxyTest and through the
 * route in DomainProxyControllerTest. The route predicates of each kind of route follow, one group
 * per kind.
 */
class DomainProxyRoutesTest {
  private static final String ID = "6c8bc359-1141-4c98-83e6-a5ca967fe180";

  private static DomainProxyRoutes.Match match(String method, String path, String query) {
    var request = new MockHttpServletRequest(method, path);
    request.setQueryString(query);
    return DomainProxyRoutes.match(request);
  }

  @Test
  void theDomainPathIsTheBrowserPathWithoutTheBffPrefix() {
    assertThat(match("GET", "/bff/api/v1/plans", null).upstreamPath()).isEqualTo("/api/v1/plans");
    assertThat(match("GET", "/content/a/b.html", null).upstreamPath())
        .isEqualTo("/content/a/b.html");
    assertThat(match("GET", "/api/v1/plans", null).upstreamPath()).isEqualTo("/api/v1/plans");
    assertThat(match("GET", "/bffx/api/v1/plans", null).upstreamPath())
        .isEqualTo("/bffx/api/v1/plans");
  }

  @Test
  void anOpenRouteIsKnownAndNeitherStaffOnlyNorRefusedForATestSession() {
    for (String path :
        new String[] {
          "/bff/api/v1/auth/me",
          "/bff/api/v1/account-catalog",
          "/bff/api/v1/support",
          "/bff/api/v1/plans",
          "/bff/api/v1/plans/java",
          "/content/a/b.html",
          "/bff/api/v1/membership/plans",
          "/bff/api/v1/sales/active",
          "/bff/api/v1/executions/capabilities"
        })
      assertThat(match("GET", path, null))
          .as(path)
          .isEqualTo(
              new DomainProxyRoutes.Match(
                  path.startsWith("/bff/") ? path.substring(4) : path,
                  false,
                  false,
                  false,
                  false,
                  path.contains("/executions/") ? 512 * 1024 : 8 * 1024 * 1024,
                  path.contains("/executions/")));
    // The account routes take any method and any query string; content is GET only.
    assertThat(match("DELETE", "/bff/api/v1/support", "a=1").unknown()).isFalse();
    assertThat(match("POST", "/content/a/b.html", null).unknown()).isTrue();
    assertThat(match("GET", "/content/a/b.html", "v=2").unknown()).isFalse();
  }

  @Test
  void aRouteThatIsNotOnAnyListIsUnknownAndAQueryStringMakesTheExactRoutesUnknown() {
    for (String path :
        new String[] {
          "/bff/api/v1/unknown", "/bff/api/v1/plansx", "/bff/api/v1/auth/csrf", "/content", "/bff/"
        }) assertThat(match("GET", path, null).unknown()).as(path).isTrue();
    for (String[] exact :
        new String[][] {
          {"GET", "/api/v1/account/permissions"},
          {"POST", "/api/v1/admin/access/admit"},
          {"GET", "/api/v1/account/access-summary"},
          {"POST", "/api/v1/executions/jobs"},
          {"POST", "/api/v1/author/review-artifacts/dlv-704/events"},
          {"POST", "/api/v1/platform-reviews"},
          {"PUT", "/api/v1/delivery/plan/inbox"},
          {"POST", "/api/v1/sweeps/run"}
        }) {
      assertThat(match(exact[0], "/bff" + exact[1], null).unknown()).as(exact[1]).isFalse();
      assertThat(match(exact[0], "/bff" + exact[1], "a=1").unknown())
          .as(exact[1] + "?a=1")
          .isTrue();
      assertThat(match(exact[0], "/bff" + exact[1], "").unknown()).as(exact[1] + "?").isTrue();
    }
    // A query string is allowed on these reads only.
    for (String read :
        new String[] {
          "/api/v1/author/review-artifacts",
          "/api/v1/platform-reviews",
          "/api/v1/delivery/plan",
          "/api/v1/admin/accounts"
        }) assertThat(match("GET", "/bff" + read, "page=2").unknown()).as(read).isFalse();
  }

  @Test
  void putIsRefusedEverywhereButOnPlatformReviewsAndTheDeliveryPlan() {
    assertThat(match("PUT", "/bff/api/v1/platform-reviews/" + ID, null).methodRefused()).isFalse();
    assertThat(match("PUT", "/bff/api/v1/platform-reviews/" + ID + "/triage", null).methodRefused())
        .isFalse();
    assertThat(match("PUT", "/bff/api/v1/delivery/plan/work-items/DLV-971", null).methodRefused())
        .isFalse();
    assertThat(match("PUT", "/bff/api/v1/delivery/plan/inbox", null).methodRefused()).isFalse();
    // Refused before the route is looked up: a known route, an unknown one, and a PUT route with a
    // query string.
    for (String path :
        new String[] {
          "/bff/api/v1/plans", "/bff/api/v1/unknown", "/bff/api/v1/delivery/plan", "/content/a"
        }) assertThat(match("PUT", path, null).methodRefused()).as(path).isTrue();
    assertThat(match("PUT", "/bff/api/v1/delivery/plan/inbox", "a=1").methodRefused()).isTrue();
    for (String method : new String[] {"GET", "POST", "DELETE"})
      assertThat(match(method, "/bff/api/v1/unknown", null).methodRefused()).as(method).isFalse();
  }

  @Test
  void staffWorkIsStaffOnlyAndTheDeliveryPlanPromoteAndSweepsAlsoRefuseATestSession() {
    for (String[] staff :
        new String[][] {
          {"GET", "/api/v1/admin/accounts"},
          {"GET", "/api/v1/author/review-artifacts"},
          {"GET", "/api/v1/platform-reviews/me"},
          {"GET", "/api/v1/account/permissions"},
          {"POST", "/api/v1/auth/invitations/activate"},
          {"GET", "/api/v1/account/access-records"},
          {"POST", "/api/v1/account/purchases"},
          {"DELETE", "/api/v1/admin/test-accounts/" + ID}
        }) {
      var match = match(staff[0], "/bff" + staff[1], null);
      assertThat(match.staffOnly()).as(staff[1]).isTrue();
      assertThat(match.testSessionRefused()).as(staff[1]).isFalse();
      assertThat(match.unknown()).as(staff[1]).isFalse();
    }
    for (String[] refused :
        new String[][] {
          {"GET", "/api/v1/delivery/plan"},
          {"POST", "/api/v1/delivery/plan/work-items"},
          {"PUT", "/api/v1/delivery/plan/inbox"},
          {"POST", "/api/v1/sweeps/run"},
          {"POST", "/api/v1/platform-reviews/" + ID + "/promote"},
          {"POST", "/api/v1/platform-reviews/REV-000001/promote"}
        }) {
      var match = match(refused[0], "/bff" + refused[1], null);
      assertThat(match.testSessionRefused()).as(refused[1]).isTrue();
      assertThat(match.staffOnly()).as(refused[1]).isTrue();
    }
    // The two public membership reads are the only membership routes open to everyone.
    assertThat(match("GET", "/bff/api/v1/membership/plans", null).staffOnly()).isFalse();
    assertThat(match("GET", "/bff/api/v1/sales/active", null).staffOnly()).isFalse();
    assertThat(match("GET", "/bff/api/v1/admin/test-accounts", null).staffOnly()).isTrue();
  }

  @Test
  void theBodyLimitFollowsTheKindOfRoute() {
    assertThat(DomainProxyRoutes.PLATFORM_REVIEW_BODY_BYTES).isEqualTo(21 * 1024 * 1024);
    for (String[] small :
        new String[][] {
          {"POST", "/api/v1/author/review-artifacts/dlv-704/events"},
          {"GET", "/api/v1/author/review-artifacts"},
          {"POST", "/api/v1/admin/access/lookup"},
          {"GET", "/api/v1/admin/access"},
          {"POST", "/api/v1/sweeps/run"}
        })
      assertThat(match(small[0], "/bff" + small[1], null).bodyLimit())
          .as(small[1])
          .isEqualTo(16 * 1024);
    for (String[] job :
        new String[][] {
          {"POST", "/api/v1/executions/jobs"}, {"DELETE", "/api/v1/executions/jobs/" + ID}
        }) {
      assertThat(match(job[0], "/bff" + job[1], null).bodyLimit()).as(job[1]).isEqualTo(512 * 1024);
      assertThat(match(job[0], "/bff" + job[1], null).execution()).as(job[1]).isTrue();
    }
    for (String[] review :
        new String[][] {
          {"POST", "/api/v1/platform-reviews"},
          {"PUT", "/api/v1/platform-reviews/" + ID},
          {"POST", "/api/v1/platform-reviews/" + ID + "/promote"}
        })
      assertThat(match(review[0], "/bff" + review[1], null).bodyLimit())
          .as(review[1])
          .isEqualTo(DomainProxyRoutes.PLATFORM_REVIEW_BODY_BYTES);
    for (String[] other :
        new String[][] {
          {"POST", "/api/v1/support"},
          {"PUT", "/api/v1/delivery/plan/inbox"},
          {"POST", "/api/v1/account/purchases"},
          {"GET", "/api/v1/admin/accounts"},
          {"GET", "/api/v1/unknown"}
        }) {
      assertThat(match(other[0], "/bff" + other[1], null).bodyLimit())
          .as(other[1])
          .isEqualTo(8 * 1024 * 1024);
      assertThat(match(other[0], "/bff" + other[1], null).execution()).as(other[1]).isFalse();
    }
    // An execution route with a query string is no execution route: unknown, and the general limit.
    assertThat(match("POST", "/bff/api/v1/executions/jobs", "a=1"))
        .isEqualTo(
            new DomainProxyRoutes.Match(
                "/api/v1/executions/jobs", false, true, false, false, 8 * 1024 * 1024, false));
  }

  @Nested
  class AuthorReview {
    private static final String base = "/bff/api/v1/author/review-artifacts";

    @Test
    void routesAreExactAndCanonical() {
      assertThat(DomainProxyRoutes.authorReviewRoute("GET", base.substring(4))).isTrue();
      for (String method : new String[] {"GET", "POST"})
        assertThat(
                DomainProxyRoutes.authorReviewRoute(method, base.substring(4) + "/dlv-704/events"))
            .isTrue();
      for (String suffix :
          new String[] {
            "/DLV-704/events",
            "/../events",
            "/a/events/extra",
            "/a%2fb/events",
            "/a/events/",
            "/" + "a".repeat(81) + "/events",
            "/a"
          })
        assertThat(DomainProxyRoutes.authorReviewRoute("GET", base.substring(4) + suffix))
            .isFalse();
      assertThat(DomainProxyRoutes.authorReviewRoute("POST", base.substring(4))).isFalse();
      assertThat(DomainProxyRoutes.authorReviewRoute("DELETE", base.substring(4) + "/a/events"))
          .isFalse();
    }
  }

  @Nested
  class Delivery {
    private static final String plan = "/api/v1/delivery/plan", items = plan + "/work-items";

    @Test
    void routesAreExact() {
      assertThat(DomainProxyRoutes.deliveryRoute("GET", plan)).isTrue();
      assertThat(DomainProxyRoutes.deliveryRoute("POST", items)).isTrue();
      for (String id :
          new String[] {"DLV-971", "a", "9", "DLV-971.2_b", "A".repeat(80), "x-".repeat(40)}) {
        assertThat(DomainProxyRoutes.deliveryRoute("PUT", items + "/" + id)).as(id).isTrue();
        assertThat(DomainProxyRoutes.deliveryRoute("POST", items + "/" + id + "/resolve-conflict"))
            .as(id)
            .isTrue();
      }
      // Malformed ids: a leading dot, underscore or hyphen, 81 characters, a slash, a space, an
      // encoded dot, nothing at all.
      for (String id :
          new String[] {
            ".DLV-971", "_x", "-x", "A".repeat(81), "DLV/971", "DLV 971", "%2e%2e", "", "DLV-971/"
          }) {
        assertThat(DomainProxyRoutes.deliveryRoute("PUT", items + "/" + id)).as(id).isFalse();
        assertThat(DomainProxyRoutes.deliveryRoute("POST", items + "/" + id + "/resolve-conflict"))
            .as(id)
            .isFalse();
      }
      for (String path :
          new String[] {
            plan + "/",
            items,
            "/api/v1/delivery",
            "/api/v1/delivery/plans",
            plan + "/../plans",
            items + "/DLV-971",
            items + "/DLV-971/resolve-conflict"
          }) assertThat(DomainProxyRoutes.deliveryRoute("GET", path)).as(path).isFalse();
      for (String path :
          new String[] {
            plan,
            items + "/",
            items + "/DLV-971",
            items + "/DLV-971/resolve-conflict/",
            items + "/DLV-971/resolve",
            items + "/DLV-971/promote"
          }) assertThat(DomainProxyRoutes.deliveryRoute("POST", path)).as(path).isFalse();
      for (String path : new String[] {plan, items, items + "/DLV-971/resolve-conflict"})
        assertThat(DomainProxyRoutes.deliveryRoute("PUT", path)).as(path).isFalse();
      // The plan inbox (owner, 2026-11-07): PUT the file, POST the sync; nothing else under /inbox.
      assertThat(DomainProxyRoutes.deliveryRoute("PUT", plan + "/inbox")).isTrue();
      assertThat(DomainProxyRoutes.deliveryRoute("POST", plan + "/inbox/sync")).isTrue();
      for (String path :
          new String[] {
            plan + "/inbox/",
            plan + "/inbox/sync",
            plan + "/inbox/plan.json",
            plan + "/inbox/../plan"
          }) assertThat(DomainProxyRoutes.deliveryRoute("PUT", path)).as(path).isFalse();
      for (String path :
          new String[] {
            plan + "/inbox", plan + "/inbox/sync/", plan + "/inbox/merge", plan + "/inbox/sync/now"
          }) assertThat(DomainProxyRoutes.deliveryRoute("POST", path)).as(path).isFalse();
      for (String path : new String[] {plan + "/inbox", plan + "/inbox/sync"}) {
        assertThat(DomainProxyRoutes.deliveryRoute("GET", path)).as(path).isFalse();
        assertThat(DomainProxyRoutes.deliveryRoute("DELETE", path)).as(path).isFalse();
      }
      for (String path :
          new String[] {plan, items, items + "/DLV-971", items + "/DLV-971/resolve-conflict"}) {
        assertThat(DomainProxyRoutes.deliveryRoute("DELETE", path)).as(path).isFalse();
        assertThat(DomainProxyRoutes.deliveryRoute("PATCH", path)).as(path).isFalse();
      }
    }
  }

  @Nested
  class PlatformReview {
    private static final String root = "/api/v1/platform-reviews";
    private static final String id = "6c8bc359-1141-4c98-83e6-a5ca967fe180";

    @Test
    void routesAreExact() {
      for (String path :
          new String[] {
            root, root + "/me", root + "/" + id, root + "/" + id + "/attachments/" + id
          }) assertThat(DomainProxyRoutes.platformReviewRoute("GET", path)).isTrue();
      assertThat(DomainProxyRoutes.platformReviewRoute("POST", root)).isTrue();
      // DLV-971: promoting a review onto the delivery plan is a POST on the exact lowercase-UUID
      // item.
      assertThat(DomainProxyRoutes.platformReviewRoute("POST", root + "/" + id + "/promote"))
          .isTrue();
      assertThat(DomainProxyRoutes.promoteRoute("POST", root + "/" + id + "/promote")).isTrue();
      for (String path :
          new String[] {
            root + "/" + id.toUpperCase() + "/promote",
            root + "/promote",
            root + "/" + id + "/promote/",
            root + "/" + id + "/promoted"
          }) {
        assertThat(DomainProxyRoutes.platformReviewRoute("POST", path)).as(path).isFalse();
        assertThat(DomainProxyRoutes.promoteRoute("POST", path)).as(path).isFalse();
      }
      for (String method : new String[] {"GET", "PUT", "DELETE"}) {
        assertThat(DomainProxyRoutes.platformReviewRoute(method, root + "/" + id + "/promote"))
            .as(method)
            .isFalse();
        assertThat(DomainProxyRoutes.promoteRoute(method, root + "/" + id + "/promote"))
            .as(method)
            .isFalse();
      }
      assertThat(DomainProxyRoutes.platformReviewRoute("PUT", root + "/" + id)).isTrue();
      assertThat(DomainProxyRoutes.platformReviewRoute("PUT", root + "/" + id + "/triage"))
          .isTrue();
      assertThat(DomainProxyRoutes.platformReviewRoute("DELETE", root + "/" + id)).isTrue();
      for (String path :
          new String[] {
            root + "/",
            root + "/" + id.toUpperCase(),
            root + "/../plans",
            root + "/" + id + "/attachments",
            root + "/" + id + "/attachments/" + id + "/x",
            root + "/me/x",
            root + "/%2e%2e"
          }) assertThat(DomainProxyRoutes.platformReviewRoute("GET", path)).isFalse();
      assertThat(DomainProxyRoutes.platformReviewRoute("POST", root + "/" + id)).isFalse();
      assertThat(DomainProxyRoutes.platformReviewRoute("DELETE", root)).isFalse();
      assertThat(DomainProxyRoutes.platformReviewRoute("PATCH", root + "/" + id)).isFalse();
      // DLV-971 (owner, 2026-11-06): the runtime record stores number their items; the same routes
      // accept REV-000001 and SUP-000001.
      for (String record : new String[] {"REV-000001", "SUP-000014", "REV-1234567"}) {
        for (String path :
            new String[] {root + "/" + record, root + "/" + record + "/attachments/" + id})
          assertThat(DomainProxyRoutes.platformReviewRoute("GET", path)).as(path).isTrue();
        assertThat(DomainProxyRoutes.platformReviewRoute("PUT", root + "/" + record))
            .as(record)
            .isTrue();
        assertThat(DomainProxyRoutes.platformReviewRoute("PUT", root + "/" + record + "/triage"))
            .as(record)
            .isTrue();
        assertThat(DomainProxyRoutes.platformReviewRoute("DELETE", root + "/" + record))
            .as(record)
            .isTrue();
        assertThat(DomainProxyRoutes.promoteRoute("POST", root + "/" + record + "/promote"))
            .as(record)
            .isTrue();
      }
      for (String bad :
          new String[] {
            "REV-00001",
            "rev-000001",
            "SUP-000001x",
            "DLV-000001",
            "REV-000001/attachments/REV-000001"
          })
        assertThat(DomainProxyRoutes.platformReviewRoute("GET", root + "/" + bad))
            .as(bad)
            .isFalse();
    }
  }

  @Nested
  class Sweeps {
    private static final String run = "/api/v1/sweeps/run";

    @Test
    void theRouteIsExact() {
      assertThat(DomainProxyRoutes.sweepsRoute("POST", run)).isTrue();
      for (String path :
          new String[] {
            run + "/",
            "/api/v1/sweeps",
            "/api/v1/sweeps/run/now",
            "/api/v1/sweeps/Run",
            "/api/v1/sweep/run",
            "/api/v1/sweeps/../sweeps/run",
            ""
          }) assertThat(DomainProxyRoutes.sweepsRoute("POST", path)).as(path).isFalse();
      for (String method : new String[] {"GET", "PUT", "DELETE", "PATCH", "HEAD"})
        assertThat(DomainProxyRoutes.sweepsRoute(method, run)).as(method).isFalse();
      assertThat(DomainProxyRoutes.deliveryRoute("POST", run)).isFalse();
      assertThat(DomainProxyRoutes.platformReviewRoute("POST", run)).isFalse();
    }
  }

  @Nested
  class Execution {
    @Test
    void onlyExplicitMethodsAndUuidJobRoutesAreAllowed() {
      String job = "/api/v1/executions/jobs/aa852488-aead-4b3d-a91f-c5d189539a52";
      assertThat(DomainProxyRoutes.executionRoute("GET", job)).isTrue();
      assertThat(DomainProxyRoutes.executionRoute("DELETE", job)).isTrue();
      assertThat(DomainProxyRoutes.executionRoute("POST", "/api/v1/executions/jobs")).isTrue();
      assertThat(DomainProxyRoutes.executionRoute("GET", "/api/v1/executions/capabilities"))
          .isTrue();
      for (String path :
          new String[] {
            "/api/v1/executions/jobs",
            job + "/extra",
            job + "?url=http://evil",
            "/api/v1/executions/secrets",
            "/api/v1/executions/jobs/../../token"
          }) {
        assertThat(DomainProxyRoutes.executionRoute("DELETE", path)).isFalse();
      }
      assertThat(DomainProxyRoutes.executionRoute("POST", job)).isFalse();
    }
  }

  @Nested
  class Membership {
    @Test
    void testAccountsExposeOnlyListAndConfirmedReset() {
      String id = "00000000-0000-0000-0000-000000000001";
      assertThat(DomainProxyRoutes.membershipRoute("GET", "/api/v1/admin/test-accounts")).isTrue();
      assertThat(DomainProxyRoutes.membershipRoute("GET", "/api/v1/admin/test-accounts/allowance"))
          .isTrue();
      assertThat(DomainProxyRoutes.membershipRoute("POST", "/api/v1/admin/test-accounts")).isTrue();
      assertThat(DomainProxyRoutes.membershipRoute("DELETE", "/api/v1/admin/test-accounts/" + id))
          .isTrue();
      assertThat(
              DomainProxyRoutes.membershipRoute(
                  "POST", "/api/v1/admin/test-accounts/" + id + "/reset"))
          .isTrue();
      for (String path :
          List.of(
              "/internal/v1/test-accounts/seed",
              "/api/v1/admin/test-accounts/not-id/reset",
              "/api/v1/admin/test-accounts/" + id + "/passwords"))
        assertThat(DomainProxyRoutes.membershipRoute("POST", path)).isFalse();
      assertThat(
              DomainProxyRoutes.membershipRoute(
                  "DELETE", "/api/v1/admin/test-accounts/" + id + "/reset"))
          .isFalse();
    }

    @Test
    void summaryRoutesAreReadOnlyAndAccountBound() {
      String id = "12345678-1234-1234-1234-123456789abc";
      assertThat(DomainProxyRoutes.membershipRoute("GET", "/api/v1/account/access-summary"))
          .isTrue();
      assertThat(
              DomainProxyRoutes.membershipRoute(
                  "GET", "/api/v1/admin/accounts/" + id + "/access-summary"))
          .isTrue();
      assertThat(DomainProxyRoutes.membershipRoute("POST", "/api/v1/account/access-summary"))
          .isFalse();
      assertThat(
              DomainProxyRoutes.membershipRoute(
                  "GET", "/api/v1/admin/accounts/not-an-id/access-summary"))
          .isFalse();
      assertThat(
              DomainProxyRoutes.membershipRoute(
                  "GET", "/api/v1/admin/accounts/" + id + "/access-summary/extra"))
          .isFalse();
    }

    @Test
    void realAccountMaintenanceRoutesAreExactAndWriteOnly() {
      String id = "12345678-1234-1234-1234-123456789abc";
      // DLV-969: the owner's Disable, Enable and Delete of DEV sign-in accounts.
      for (String action : List.of("downgrade", "delete", "disable", "enable", "remove")) {
        assertThat(
                DomainProxyRoutes.membershipRoute(
                    "POST", "/api/v1/admin/accounts/" + id + "/" + action))
            .isTrue();
        assertThat(
                DomainProxyRoutes.membershipRoute(
                    "GET", "/api/v1/admin/accounts/" + id + "/" + action))
            .isFalse();
        assertThat(
                DomainProxyRoutes.membershipRoute(
                    "POST", "/api/v1/admin/accounts/not-an-id/" + action))
            .isFalse();
      }
    }

    @Test
    void exactPublicAndWriteRoutes() {
      assertThat(DomainProxyRoutes.membershipRoute("GET", "/api/v1/membership/plans")).isTrue();
      assertThat(DomainProxyRoutes.membershipRoute("GET", "/api/v1/plans")).isFalse();
      assertThat(DomainProxyRoutes.membershipRoute("POST", "/api/v1/account/purchases")).isTrue();
      assertThat(DomainProxyRoutes.membershipRoute("POST", "/api/v1/account/purchases/quote"))
          .isTrue();
      assertThat(DomainProxyRoutes.membershipRoute("DELETE", "/api/v1/account/purchases"))
          .isFalse();
      assertThat(DomainProxyRoutes.membershipRoute("POST", "/api/v1/membership/plans")).isFalse();
      assertThat(
              DomainProxyRoutes.membershipRoute(
                  "GET", "/api/v1/admin/accounts/not-a-uuid/access-records"))
          .isFalse();
    }
  }
}
