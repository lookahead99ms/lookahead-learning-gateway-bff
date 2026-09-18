package com.lookahead.learning.content.gateway;

import org.junit.jupiter.api.Test;
import java.net.URI;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class AuthorPreviewPathTest {
    private static final URI UPSTREAM = URI.create("http://127.0.0.1:4315");

    @Test void preservesSafeNestedPathsAndRawQueriesUnderTheFixedOrigin() {
        var target = AuthorPreviewPath.target(UPSTREAM,
                "/bff/author/previews/design%20notes/example+(1).html", "theme=dark&label=a%20b&label=c+d");
        assertThat(target.toASCIIString()).isEqualTo(
                "http://127.0.0.1:4315/design%20notes/example+(1).html?theme=dark&label=a%20b&label=c+d");
        assertThat(AuthorPreviewPath.target(UPSTREAM, "/bff/author/previews/focus-studio/", null).getRawPath())
                .isEqualTo("/focus-studio/");
        assertThat(AuthorPreviewPath.target(UPSTREAM, "/bff/author/previews/", null).getRawPath()).isEqualTo("/");
    }

    @Test void rejectsTraversalEncodedSeparatorsAndExternalPaths() {
        for (String relative : new String[]{"../secret", "./index.html", "a/../secret", "%2e%2e/secret",
                "%2E%2E/secret", "%252e%252e/secret", "%2e./secret", "a%2fb.html", "a%2Fb.html",
                "a%5cb.html", "%255csecret", "a//b.html", "/other.test/index.html", "https://other.test/a",
                "a\\b.html", "a%00.html", "a%0a.html", "a%7f.html", "a%FF.html", "a%xx.html",
                "a%.html", "a b.html", "a#fragment", "a;param.html"}) {
            assertThatIllegalArgumentException().as(relative).isThrownBy(() ->
                    AuthorPreviewPath.target(UPSTREAM, AuthorPreviewPath.PREFIX + relative, null));
        }
        for (String path : new String[]{null, "/private-previews/index.html", "https://other.test/index.html",
                "/bff/author/previews", AuthorPreviewPath.PREFIX + "a".repeat(2048)}) {
            assertThatIllegalArgumentException().as(String.valueOf(path)).isThrownBy(() ->
                    AuthorPreviewPath.target(UPSTREAM, path, null));
        }
    }

    @Test void rejectsMalformedOrUnboundedQueriesAndCannotSelectAnotherOrigin() {
        for (String query : new String[]{"q=" + "a".repeat(4096), "q=a b", "q=%00", "q=%0D%0AHost%3Aother.test",
                "q=%7F", "q=%", "q=%xx", "q=#fragment", "q=\\other.test"}) {
            assertThatIllegalArgumentException().as(query).isThrownBy(() ->
                    AuthorPreviewPath.target(UPSTREAM, AuthorPreviewPath.PREFIX + "index.html", query));
        }
        var target = AuthorPreviewPath.target(UPSTREAM, AuthorPreviewPath.PREFIX + "index.html",
                "target=https%3A%2F%2Fother.test%2Fprivate&url=//other.test");
        assertThat(target.getRawAuthority()).isEqualTo("127.0.0.1:4315");
        assertThat(target.getRawPath()).isEqualTo("/index.html");
    }
}
