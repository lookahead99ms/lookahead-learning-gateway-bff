package com.lookahead.gateway.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpResponse;

/**
 * DLV-1015: the answer headers DevWebProxy and AccountMergeProxy each built with the same three
 * statements.
 */
class UpstreamAnswerHeadersTest {
  @Test
  void theAnswerIsNeverCachedNeverSniffedAndKeepsTheUpstreamsContentTypeInThatOrder() {
    var received = new MockClientHttpResponse(new byte[0], HttpStatus.OK);
    received.getHeaders().setContentType(MediaType.parseMediaType("text/html;charset=UTF-8"));
    received.getHeaders().set("Set-Cookie", "upstream=1");
    received.getHeaders().set("Location", "https://elsewhere.example");
    var headers = UpstreamAnswerHeaders.from(received);
    assertThat(headers.headerNames().stream().toList())
        .isEqualTo(List.of("Cache-Control", "X-Content-Type-Options", "Content-Type"));
    assertThat(headers.getFirst("Cache-Control")).isEqualTo("no-store");
    assertThat(headers.getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
    assertThat(headers.getFirst("Content-Type")).isEqualTo("text/html;charset=UTF-8");
  }

  @Test
  void anAnswerWithoutAContentTypeGetsNoneAndAnUnreadableOneIsNotPassedOn() {
    var bare =
        UpstreamAnswerHeaders.from(new MockClientHttpResponse(new byte[0], HttpStatus.NO_CONTENT));
    assertThat(bare.headerNames().stream().toList())
        .isEqualTo(List.of("Cache-Control", "X-Content-Type-Options"));
    var unreadable = new MockClientHttpResponse(new byte[0], HttpStatus.OK);
    unreadable.getHeaders().set("Content-Type", "not a media type");
    assertThatThrownBy(() -> UpstreamAnswerHeaders.from(unreadable))
        .isInstanceOf(InvalidMediaTypeException.class);
  }
}
