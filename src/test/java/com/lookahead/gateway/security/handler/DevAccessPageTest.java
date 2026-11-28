package com.lookahead.gateway.security.handler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * DLV-1015: the DEV gate page on its own: the template with its three marks, the policy hash of its
 * one style block and the fixed notices. No request and no handler is involved here. The page as
 * the gate's route serves it (headers, the Google switch read at start) is in DevAccessHandlerTest
 * and, through the route methods, in DevAccessControllerTest.
 */
class DevAccessPageTest {
  static final String TEMPLATE =
      "<style>a{}</style><h1>DEV</h1><!--notice-->"
          + "<!--google--><a>Google</a><!--/google--><p>end</p>";

  static String sha256(String text) throws Exception {
    return Base64.getEncoder()
        .encodeToString(
            MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void thePolicyAdmitsExactlyThePagesOwnStyleBlockByItsHash() throws Exception {
    assertThat(DevAccessPage.BASE_POLICY)
        .isEqualTo("default-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    var page = new DevAccessPage(TEMPLATE);
    assertThat(page.html).isEqualTo(TEMPLATE);
    assertThat(page.policy)
        .isEqualTo(
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; style-src 'sha256-"
                + sha256("a{}")
                + "'");
    // The hash is over the exact text between the tags: white space counts, and an empty block has
    // the hash of nothing.
    assertThat(DevAccessPage.styleHash("<style>a{}</style>")).isEqualTo(sha256("a{}"));
    assertThat(
            DevAccessPage.styleHash(
                "<p>before</p><style>\n a { color: red }\n</style><p>after</p>"))
        .isEqualTo(sha256("\n a { color: red }\n"));
    assertThat(DevAccessPage.styleHash("<style></style>"))
        .isEqualTo("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    assertThat(DevAccessPage.styleHash("<style>é</style>")).isEqualTo(sha256("é"));
  }

  @Test
  void aPageWithoutExactlyOneStyleBlockIsRefused() {
    for (String html :
        List.of(
            "<html><body>no style</body></html>",
            "<style>never closed",
            "<style>a</style><style>b</style>",
            "<style>a</style><style media=\"print\">b</style>",
            "<style media=\"print\">a</style>",
            ""))
      assertThatThrownBy(() -> DevAccessPage.styleHash(html))
          .as(html)
          .isExactlyInstanceOf(IllegalStateException.class)
          .hasMessage("The page must carry exactly one <style> block");
    assertThatThrownBy(
            () -> new DevAccessPage("<p>no style</p><!--notice--><!--google--><!--/google-->"))
        .isExactlyInstanceOf(IllegalStateException.class);
  }

  @Test
  void theGoogleBlockIsKeptOrCutOutAndTheNoticeGoesWhereItsMarkIs() {
    var page = new DevAccessPage(TEMPLATE);
    assertThat(page.render(true, DevAccessPage.Notice.NONE))
        .isEqualTo("<style>a{}</style><h1>DEV</h1><a>Google</a><p>end</p>");
    assertThat(page.render(false, DevAccessPage.Notice.NONE))
        .isEqualTo("<style>a{}</style><h1>DEV</h1><p>end</p>");
    assertThat(page.render(false, DevAccessPage.Notice.PENDING))
        .isEqualTo(
            "<style>a{}</style><h1>DEV</h1><p class=\"notice\" role=\"status\">Your sign-in worked."
                + " The owner has to approve your access before DEV opens. Sign in again once you"
                + " hear back.</p><p>end</p>");
    assertThat(page.render(true, DevAccessPage.Notice.FAILED))
        .isEqualTo(
            "<style>a{}</style><h1>DEV</h1><p class=\"notice\" role=\"status\">"
                + "That sign-in did not complete. Try again.</p><a>Google</a><p>end</p>");
    // Rendering changes neither the template nor the policy: the style block is the same with and
    // without Google.
    assertThat(page.html).isEqualTo(TEMPLATE);
    assertThat(DevAccessPage.styleHash(page.render(true, DevAccessPage.Notice.PENDING)))
        .isEqualTo(DevAccessPage.styleHash(TEMPLATE));
  }

  @Test
  void aTemplateWithoutItsThreeMarksInOrderIsRefusedWhenItIsRendered() {
    for (String html :
        List.of(
            "<style>a</style><p>no marks</p>",
            "<style>a</style><!--google--><a>G</a><!--/google-->",
            "<style>a</style><!--notice--><a>G</a><!--/google-->",
            "<style>a</style><!--notice--><!--google--><a>G</a>",
            "<style>a</style><!--notice--><!--/google--><!--google-->"))
      for (boolean google : new boolean[] {true, false})
        assertThatThrownBy(() -> new DevAccessPage(html).render(google, DevAccessPage.Notice.NONE))
            .as(html)
            .isExactlyInstanceOf(IllegalStateException.class)
            .hasMessage("The page must carry the notice and Google marks");
  }

  @Test
  void theNoticeIsPendingForAccessPendingElseFailedForAnyErrorElseNone() {
    assertThat(DevAccessPage.Notice.from(null, null)).isEqualTo(DevAccessPage.Notice.NONE);
    assertThat(DevAccessPage.Notice.from("other", null)).isEqualTo(DevAccessPage.Notice.NONE);
    assertThat(DevAccessPage.Notice.from("PENDING", null)).isEqualTo(DevAccessPage.Notice.NONE);
    assertThat(DevAccessPage.Notice.from("pending", null)).isEqualTo(DevAccessPage.Notice.PENDING);
    assertThat(DevAccessPage.Notice.from("pending", "signin"))
        .isEqualTo(DevAccessPage.Notice.PENDING);
    assertThat(DevAccessPage.Notice.from(null, "signin")).isEqualTo(DevAccessPage.Notice.FAILED);
    assertThat(DevAccessPage.Notice.from(null, "")).isEqualTo(DevAccessPage.Notice.FAILED);
    assertThat(DevAccessPage.Notice.from("other", "<b>anything</b>"))
        .isEqualTo(DevAccessPage.Notice.FAILED);
    // The words are fixed text of ours; what the request sent is never part of them.
    assertThat(DevAccessPage.Notice.NONE.text).isEmpty();
    assertThat(DevAccessPage.Notice.PENDING.text)
        .isEqualTo(
            "Your sign-in worked. The owner has to approve your access before DEV opens. Sign in"
                + " again once you hear back.");
    assertThat(DevAccessPage.Notice.FAILED.text)
        .isEqualTo("That sign-in did not complete. Try again.");
    assertThat(DevAccessPage.Notice.values()).hasSize(3);
  }

  @Test
  void theShippedPageLoadsCarriesItsMarksAndRendersWithoutThemForEverySwitchAndNotice()
      throws Exception {
    assertThat(DevAccessPage.RESOURCE).isEqualTo("dev-access.html");
    var page = DevAccessPage.load(DevAccessPage.RESOURCE);
    assertThat(page.html)
        .startsWith("<!doctype html>")
        .contains(DevAccessPage.NOTICE_MARK, DevAccessPage.GOOGLE_START, DevAccessPage.GOOGLE_END);
    String css =
        page.html.substring(
            page.html.indexOf("<style>") + "<style>".length(), page.html.indexOf("</style>"));
    assertThat(page.policy)
        .isEqualTo(DevAccessPage.BASE_POLICY + "; style-src 'sha256-" + sha256(css) + "'");
    for (boolean google : new boolean[] {true, false})
      for (var notice : DevAccessPage.Notice.values()) {
        String served = page.render(google, notice);
        assertThat(served)
            .as(google + " " + notice)
            .doesNotContain("<!--")
            .doesNotContain("<script");
        assertThat(served.contains("Continue with Google")).isEqualTo(google);
        assertThat(served.contains("class=\"notice\""))
            .isEqualTo(notice != DevAccessPage.Notice.NONE);
        if (notice != DevAccessPage.Notice.NONE)
          assertThat(served)
              .contains("<p class=\"notice\" role=\"status\">" + notice.text + "</p>");
        // What is served still carries the one style block the policy admits.
        assertThat(DevAccessPage.styleHash(served)).isEqualTo(sha256(css));
      }
  }

  @Test
  void aMissingResourceIsRefusedByName() {
    assertThatThrownBy(() -> DevAccessPage.load("dev-access-missing.html"))
        .isExactlyInstanceOf(IllegalStateException.class)
        .hasMessage("Missing classpath resource dev-access-missing.html");
  }
}
