package com.lookahead.gateway.util;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import tools.jackson.databind.json.JsonMapper;

/**
 * DLV-1015: the three checks around the account-merge offer, driven directly. The offer through a
 * whole sign-in is in SignInSuccessHandlerTest, PasswordSignInHandlerTest, AccountCloudProxyTest
 * and GatewayBffApplicationCloudIntegrationTest.
 */
class AccountMergeOfferTest {
  @Test
  void theTwoAttributeNamesAreWhatSessionsAndRequestsAlreadyCarry() {
    assertThat(AccountMergeOffer.MERGE_AVAILABLE).isEqualTo("lookaheadMergeAvailable");
    assertThat(AccountMergeOffer.MERGE_AFTER_CHALLENGE).isEqualTo("lookaheadMergeAfterChallenge");
  }

  @Test
  void theOfferCountsOnlyWhenThisRequestCarriesTheBooleanTrue() {
    var request = new MockHttpServletRequest();
    assertThat(AccountMergeOffer.mergeAvailable(request)).isFalse();
    request.setAttribute(AccountMergeOffer.MERGE_AVAILABLE, Boolean.TRUE);
    assertThat(AccountMergeOffer.mergeAvailable(request)).isTrue();
    for (Object other : new Object[] {Boolean.FALSE, "true", 1, new Object()}) {
      request.setAttribute(AccountMergeOffer.MERGE_AVAILABLE, other);
      assertThat(AccountMergeOffer.mergeAvailable(request)).as(String.valueOf(other)).isFalse();
    }
    // The session's attributes are not the request's: neither name there makes this request an
    // offer.
    var held = new MockHttpServletRequest();
    held.getSession(true).setAttribute(AccountMergeOffer.MERGE_AVAILABLE, Boolean.TRUE);
    held.getSession().setAttribute(AccountMergeOffer.MERGE_AFTER_CHALLENGE, Boolean.TRUE);
    assertThat(AccountMergeOffer.mergeAvailable(held)).isFalse();
  }

  @Test
  void onlyAJsonBooleanTrueIsALiteralTrue() {
    var answer =
        new JsonMapper()
            .readTree(
                "{\"yes\":true,\"no\":false,\"text\":\"true\""
                    + ",\"number\":1,\"nothing\":null"
                    + ",\"object\":{\"mergeAvailable\":true},\"list\":[true]}");
    assertThat(AccountMergeOffer.literalTrue(answer.get("yes"))).isTrue();
    for (String field : new String[] {"no", "text", "number", "nothing", "object", "list"})
      assertThat(AccountMergeOffer.literalTrue(answer.get(field))).as(field).isFalse();
    // A field the answer does not have, read either way, and no answer at all.
    assertThat(AccountMergeOffer.literalTrue(answer.get("missing"))).isFalse();
    assertThat(AccountMergeOffer.literalTrue(answer.path("missing"))).isFalse();
    assertThat(AccountMergeOffer.literalTrue(null)).isFalse();
  }

  @Test
  void aMergeTargetWithItsOwnQueryStaysAndAnythingElseBecomesTheOffer() {
    assertThat(AccountMergeOffer.mergeOffer("/account/merge?token=synthetic-token"))
        .isEqualTo("/account/merge?token=synthetic-token");
    assertThat(AccountMergeOffer.mergeOffer("/account/merge?offer=1"))
        .isEqualTo("/account/merge?offer=1");
    assertThat(AccountMergeOffer.mergeOffer("/account/merge?token=synthetic-token&offer=1"))
        .isEqualTo("/account/merge?token=synthetic-token&offer=1");
    for (String next :
        new String[] {
          "/account/merge", "/account/merge/", "/learn", "/", "", "/account/merged?token=x"
        })
      assertThat(AccountMergeOffer.mergeOffer(next)).as(next).isEqualTo("/account/merge?offer=1");
  }
}
