package com.lookahead.gateway.security.handler;

import com.lookahead.gateway.client.SignInDomainClient;
import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientRegistrationFactory;
import com.lookahead.gateway.security.session.DevAccessGate;
import com.lookahead.gateway.security.session.DevAccessSession;
import com.lookahead.gateway.security.session.SignInProofSession;
import com.lookahead.gateway.security.session.SignInSession;
import com.lookahead.gateway.util.AccountMergeOffer;
import com.lookahead.gateway.util.SignInReturnDestination;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import tools.jackson.databind.json.JsonMapper;

/**
 * What happens once a sign-in is accepted, for the OAuth callback and our own password page alike;
 * a bean both of them receive.
 */
public final class SignInCompletionHandler {
  private final OAuthClientDetails oauth;
  private final OAuth2AuthorizedClientRepository clients;
  private final SignInDomainClient domainClient;
  private final Optional<DevAccessGate> gate;

  public SignInCompletionHandler(
      OAuthClientDetails oauth,
      OAuth2AuthorizedClientRepository clients,
      SignInDomainClient domainClient,
      Optional<DevAccessGate> gate) {
    this.oauth = oauth;
    this.clients = clients;
    this.domainClient = domainClient;
    this.gate = gate;
  }

  /**
   * Domain answered 403 ACCOUNT_ADMISSION_REQUIRED: the sign-in worked, the account waits for the
   * owner (DLV-969).
   */
  static final class AdmissionPending extends IllegalStateException {
    AdmissionPending() {
      super("Account admission pending");
    }
  }

  /**
   * DLV-971 (owner, 2026-11-06): the Welcome page greets a waiting person by first name. The
   * learner sign-in ends here and no session survives, so the name travels in a short-lived cookie
   * the Welcome page reads once and clears; never in the redirect's URL. Not HttpOnly on purpose
   * (the page reads it); SameSite=Strict, 15 minutes, nothing else in it.
   */
  static final String WELCOME_COOKIE = "lookahead-welcome";

  static final Duration WELCOME_COOKIE_AGE = Duration.ofMinutes(15);

  /**
   * The first name from the provider's claims: given_name, else the first word of name; letters
   * only, at most 40.
   */
  static String firstName(Authentication authentication) {
    if (authentication == null || !(authentication.getPrincipal() instanceof OidcUser user))
      return null;
    String given = user.getGivenName();
    String full = user.getFullName();
    String candidate =
        given != null && !given.isBlank()
            ? given.strip()
            : full == null ? "" : full.strip().split("\\s+")[0];
    return candidate.isEmpty()
            || candidate.length() > 40
            || !candidate.matches("[\\p{L}\\p{M}'\\u2019.-]+")
        ? null
        : candidate;
  }

  static void welcomeName(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    String first = firstName(authentication);
    if (first == null) return;
    var cookie =
        ResponseCookie.from(WELCOME_COOKIE, URLEncoder.encode(first, StandardCharsets.UTF_8))
            .path("/")
            .maxAge(WELCOME_COOKIE_AGE)
            .sameSite("Strict")
            .secure(request.isSecure())
            .httpOnly(false)
            .build();
    response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
  }

  /**
   * {@code google} for a Cognito user federated from Google; otherwise {@code password} (the pool's
   * own email and password).
   */
  static String provider(Authentication authentication) {
    if (authentication.getPrincipal() instanceof OidcUser user) {
      if (user.getClaims().get("identities") instanceof Collection<?> identities)
        for (Object identity : identities)
          if (identity instanceof Map<?, ?> map
              && "google".equalsIgnoreCase(String.valueOf(map.get("providerName"))))
            return "google";
      String username = user.getClaimAsString("cognito:username");
      if (username != null && username.toLowerCase(Locale.ROOT).startsWith("google_"))
        return "google";
    }
    return "password";
  }

  /**
   * The one sign-in completion shared by the OAuth callback and our own password page (DLV-969):
   * DEV gate freshness, Domain admission, waiting accounts and sign-in challenges. Returns the
   * same-origin path the browser goes to next; the OAuth callback redirects to it, the password
   * route returns it as JSON.
   */
  public String completeSignIn(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    var session = request.getSession();
    session.setAttribute(SignInSession.LAST_ACTIVITY, Instant.now());
    // DLV-969: which provider and which door (the OAuth callback or our own password page), for the
    // log line.
    String provider = oauth.cloud() ? provider(authentication) : "identity";
    String via =
        request.getRequestURI() != null && request.getRequestURI().startsWith("/login/oauth2/code/")
            ? "oauth"
            : "password-page";
    if (oauth.cloud()) {
      // DLV-969 (README decision 2): the DEV gate stays open only for an account Domain admits. The
      // fresh-sign-in check runs first; a refusal below puts back the gate this browser held
      // before, or none for a waiting account.
      Object previousGate = DevAccessSession.current(request);
      // The step that refused the sign-in, as a stable code for the log line; set before each step
      // that can refuse.
      String reason = "DEV_GATE_REFUSED";
      Integer domainStatus = null;
      try {
        if (gate.isPresent() && authentication.getPrincipal() instanceof OidcUser user)
          gate.get().admit(request, user);
        reason = "MISSING_PROVIDER_TOKENS";
        var client =
            clients.<OAuth2AuthorizedClient>loadAuthorizedClient(
                OAuthClientRegistrationFactory.REGISTRATION_ID, authentication, request);
        if (client == null) throw new IllegalStateException("Missing provider tokens");
        SignInProofSession.proof(request, true);
        reason = "DOMAIN_UNAVAILABLE";
        var admission =
            domainClient.call(
                "admit",
                client.getAccessToken().getTokenValue(),
                SignInProofSession.proof(request, false),
                SignInProofSession.challenge(request),
                Map.of());
        domainStatus = admission.status();
        if (admission.status() != 200) {
          String code = OpsLog.code(admission.body());
          reason = code == null ? "DOMAIN_REFUSED" : code;
        }
        if (admission.status() == 403
            && "ACCOUNT_ADMISSION_REQUIRED"
                .equals(new JsonMapper().readTree(admission.body()).path("code").asString("")))
          throw new AdmissionPending();
        if (admission.status() != 200) throw new IllegalStateException("Domain rejected admission");
        reason = "INVALID_DOMAIN_ANSWER";
        String challenge = admission.data().path("challengeToken").asString("");
        // DLV-969 S36: a fresh admission decides afresh; an offer left by an earlier challenge
        // never carries over.
        request.getSession().removeAttribute(AccountMergeOffer.MERGE_AFTER_CHALLENGE);
        if (!challenge.isEmpty()) {
          // DLV-969 S36: still at the challenge, so no offer yet; the replace answer carries it
          // once resolved.
          if (!challenge.matches("[A-Za-z0-9_-]{43}"))
            throw new IllegalStateException("Invalid challenge");
          session = request.getSession();
          session.setAttribute(SignInProofSession.CHALLENGE, challenge);
          Object saved = session.getAttribute(SignInReturnDestination.SESSION_ATTRIBUTE);
          String destination =
              SignInReturnDestination.safeReturn(saved instanceof String value ? value : null);
          OpsLog.success("sign-in.completed")
              .addKeyValue("provider", provider)
              .addKeyValue("via", via)
              .addKeyValue("next", "SIGN_IN_CHALLENGE")
              .log(
                  "Sign-in accepted ({} via {}), but the person must first choose which active"
                      + " sign-in to end (sign-in limit reached)",
                  provider,
                  via);
          return "/sign-in/choose?returnTo="
              + URLEncoder.encode(destination, StandardCharsets.UTF_8);
        }
        if (admission.data().path("signInId").asString("").isEmpty())
          throw new IllegalStateException("Missing admission");
        request.getSession().removeAttribute(SignInProofSession.CHALLENGE);
        // DLV-969 S36: only an admitted sign-in (never a waiting or challenged one) carries the
        // merge offer on.
        boolean merge = AccountMergeOffer.literalTrue(admission.data().path("mergeAvailable"));
        if (merge) request.setAttribute(AccountMergeOffer.MERGE_AVAILABLE, Boolean.TRUE);
        OpsLog.success("sign-in.completed")
            .addKeyValue("provider", provider)
            .addKeyValue("via", via)
            .addKeyValue("merge.available", merge)
            .log(
                merge
                    ? "Sign-in completed ({} via {}): Domain admitted the account and other"
                        + " accounts share its verified email (merge offered)"
                    : "Sign-in completed ({} via {}): Domain admitted the account",
                provider,
                via);
      } catch (RuntimeException rejected) {
        boolean pending = rejected instanceof AdmissionPending;
        if (pending) reason = "ACCOUNT_ADMISSION_REQUIRED";
        var line =
            ("DOMAIN_UNAVAILABLE".equals(reason)
                    ? OpsLog.failed("sign-in.completed", reason)
                    : OpsLog.refused("sign-in.completed", reason))
                .addKeyValue("provider", provider)
                .addKeyValue("via", via);
        if (domainStatus != null) line = line.addKeyValue("upstream.status", domainStatus);
        if (pending)
          line.log(
              "Sign-in refused by Domain ({} via {}): ACCOUNT_ADMISSION_REQUIRED, the account is"
                  + " waiting for the owner to admit it",
              provider,
              via);
        else if ("DOMAIN_UNAVAILABLE".equals(reason))
          line.addKeyValue("exception.types", OpsLog.types(rejected))
              .log(
                  "Sign-in failed ({} via {}): Domain did not answer the admission check ({})",
                  provider,
                  via,
                  OpsLog.types(rejected));
        else line.log("Sign-in refused ({} via {}): {}", provider, via, reason);
        clients.removeAuthorizedClient(
            OAuthClientRegistrationFactory.REGISTRATION_ID, authentication, request, response);
        if (pending) welcomeName(request, response, authentication);
        if (gate.isPresent()) {
          // A waiting account never rides on a gate opened by an earlier sign-in in this browser.
          Object kept = pending ? null : previousGate;
          DevAccessSession.restore(request, kept);
          // DLV-969: a waiting account sees the Look Ahead essence on /welcome while it waits; the
          // gate card /dev/access?access=pending still renders the same notice as a fallback.
          if (pending) return "/welcome?access=pending";
          return DevAccessSession.open(kept, Instant.now())
              ? "/sign-in?error=admission"
              : "/dev/access?error=signin";
        }
        // No gate (PROD): end the learner sign-in; a waiting account lands on the landing page
        // notice.
        DevAccessSession.clearLearner(request);
        if (pending) return "/?access=pending";
        return "/sign-in?error=admission";
      }
    }
    session = request.getSession();
    Object saved = session.getAttribute(SignInReturnDestination.SESSION_ATTRIBUTE);
    session.removeAttribute(SignInReturnDestination.SESSION_ATTRIBUTE);
    if (!oauth.cloud())
      OpsLog.success("sign-in.completed")
          .addKeyValue("provider", provider)
          .addKeyValue("via", via)
          .log("Sign-in completed ({} via {})", provider, via);
    return SignInReturnDestination.safeReturn(saved instanceof String value ? value : null);
  }
}
