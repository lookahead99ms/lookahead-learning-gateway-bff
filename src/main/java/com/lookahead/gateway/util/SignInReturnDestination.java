package com.lookahead.gateway.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Pattern;

/** Where a browser may be sent after sign-in: only known paths of our own site, anything else becomes {@code /}. */
public final class SignInReturnDestination {
    /** The session attribute that keeps the destination asked for at the start of a sign-in until the sign-in completes. */
    public static final String SESSION_ATTRIBUTE = "learningReturnTo";

    private SignInReturnDestination() {}

    /** DLV-969 S36: {@code token=<43 url-safe>} and/or {@code offer=1}, each at most once, in either order. */
    private static final Pattern MERGE_QUERY = Pattern.compile(
            "token=[A-Za-z0-9_-]{43}|offer=1|token=[A-Za-z0-9_-]{43}&offer=1|offer=1&token=[A-Za-z0-9_-]{43}");

    public static String safeReturn(String value) {
        if (value == null || !value.startsWith("/") || unsafeRedirectCharacters(value)) return "/";
        try {
            var destination = new URI(value);
            String path = destination.getPath();
            if (destination.isAbsolute() || destination.getRawAuthority() != null || path == null
                    || path.matches(".*(?:^|/)\\.{1,2}(?:/.*|$)")
                    || unsafeRedirectCharacters(path) || unsafeRedirectCharacters(destination.getQuery())
                    || unsafeRedirectCharacters(destination.getFragment())) return "/";
            // DLV-969 S36: the merge page, unencoded, with only its email token and/or the offer flag and no fragment.
            if (path.equals("/account/merge"))
                return value.startsWith("/account/merge") && "/account/merge".equals(destination.getRawPath()) && destination.getRawFragment() == null
                        && (destination.getRawQuery() == null || MERGE_QUERY.matcher(destination.getRawQuery()).matches()) ? value : "/";
            // DLV-931: the catalog route is /blaze; /look-ahead stays accepted for old bookmarks and open tabs.
            return path.equals("/") || path.equals("/account") || path.equals("/pricing") || path.equals("/delivery-plan")
                    || path.matches("^/(?:study-plan|learn|grow|blaze|look-ahead|search|support|author|admin)(?:/.*)?$")
                    ? value : "/";
        } catch (URISyntaxException invalidDestination) {
            return "/";
        }
    }

    private static boolean unsafeRedirectCharacters(String value) {
        return value != null && (value.indexOf('\\') >= 0
                || value.codePoints().anyMatch(Character::isISOControl));
    }
}
