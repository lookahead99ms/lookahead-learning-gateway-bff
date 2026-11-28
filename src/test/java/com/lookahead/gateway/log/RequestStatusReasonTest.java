package com.lookahead.gateway.log;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * DLV-1015: the response wrapper that keeps why a request failed, driven directly: the code and the
 * words it reads from a failure answer, what it falls back to, the reference, the 4 KB limit, and
 * that a success is never copied. How the request's summary line uses the reason (its level, its
 * sentence) is in RequestLogTest.
 */
class RequestStatusReasonTest {
  final MockHttpServletResponse answer = new MockHttpServletResponse();
  final RequestStatusReason watched = new RequestStatusReason(answer);

  static RequestStatusReason failure(int status, String body) throws Exception {
    var watched = new RequestStatusReason(new MockHttpServletResponse());
    watched.setStatus(status);
    watched.getWriter().write(body);
    return watched;
  }

  @Test
  void aSuccessHasNoReasonAndNoReferenceAndNothingOfItIsKept() throws Exception {
    assertThat(watched.reason()).isNull();
    assertThat(watched.reference()).isNull();
    watched
        .getWriter()
        .write(
            "{\"code\":\"NOT_AN_ERROR\",\"message\":\"All"
                + " good.\",\"reference\":\"7f1a2c3d-aaaa-4bbb-8ccc-dddddddddddd\"}");
    watched.setStatus(302);
    assertThat(watched.reason()).isNull();
    assertThat(watched.reference()).isNull();
    // What was written before the status became a failure was never copied, so a later failure
    // status has only its own words.
    watched.setStatus(404);
    assertThat(watched.reason())
        .isEqualTo(
            new RequestStatusReason.Reason("HTTP_404", "Not found: no such page, record or route"));
    assertThat(watched.reference()).isNull();
    assertThat(answer.getContentAsString()).contains("NOT_AN_ERROR");
  }

  @Test
  void theReasonIsTheAnswersOwnCodeAndWords() throws Exception {
    assertThat(
            failure(
                    409,
                    "{\"status\":409,\"code\":\"PLAN_EXISTS\",\"message\":\"A plan with this name"
                        + " exists.\"}")
                .reason())
        .isEqualTo(new RequestStatusReason.Reason("PLAN_EXISTS", "A plan with this name exists."));
    // The words may come under any of four names; without a code the status stands in for it.
    for (String name : List.of("message", "detail", "error_description", "title"))
      assertThat(failure(400, "{\"" + name + "\" : \"The form was incomplete.\"}").reason())
          .as(name)
          .isEqualTo(new RequestStatusReason.Reason("HTTP_400", "The form was incomplete."));
    // A code without words: the status in words.
    assertThat(failure(403, "{\"code\":\"DELETE_FORBIDDEN\"}").reason())
        .isEqualTo(
            new RequestStatusReason.Reason(
                "DELETE_FORBIDDEN",
                "Not allowed: a role, CSRF token, DEV gate or ownership rule refused it"));
    // A code that is not one (a space, or longer than 80) is not taken.
    assertThat(failure(400, "{\"code\":\"not a code\"}").reason().code()).isEqualTo("HTTP_400");
    assertThat(failure(400, "{\"code\":\"" + "A".repeat(81) + "\"}").reason().code())
        .isEqualTo("HTTP_400");
    // Quotes inside the words are unescaped; a line break or tab becomes a space; an email address
    // is masked.
    assertThat(
            failure(422, "{\"message\":\"The name \\\"x\\\" is taken\tby priya@example.invalid.\"}")
                .reason()
                .words())
        .isEqualTo("The name \"x\" is taken by [email].");
  }

  @Test
  void withoutABodyTheReasonIsTheSendErrorMessageElseTheStatusInWords() throws Exception {
    watched.sendError(401, "Full authentication is required");
    assertThat(watched.reason())
        .isEqualTo(new RequestStatusReason.Reason("HTTP_401", "Full authentication is required"));
    assertThat(answer.getStatus()).isEqualTo(401);
    assertThat(answer.getErrorMessage()).isEqualTo("Full authentication is required");
    var blank = new RequestStatusReason(new MockHttpServletResponse());
    blank.sendError(503, " ");
    assertThat(blank.reason())
        .isEqualTo(
            new RequestStatusReason.Reason(
                "HTTP_503", "Unavailable: a service this request needs is down or busy"));
    var bare = new RequestStatusReason(new MockHttpServletResponse());
    bare.setStatus(418);
    assertThat(bare.reason()).isEqualTo(new RequestStatusReason.Reason("HTTP_418", "HTTP 418"));
    // A long message is cut at 300 characters; the answer's own words win over the sendError
    // message.
    var wordy = new RequestStatusReason(new MockHttpServletResponse());
    wordy.sendError(400, "x".repeat(400));
    assertThat(wordy.reason().words()).isEqualTo("x".repeat(300) + "…");
    var both = failure(400, "{\"message\":\"From the body.\"}");
    both.sendError(400, "From sendError.");
    assertThat(both.reason().words()).isEqualTo("From the body.");
  }

  @Test
  void theReferenceIsReadFromAFailureAnswerOnly() throws Exception {
    String body =
        "{\"code\":\"ACCOUNT_STORAGE_UNAVAILABLE\","
            + "\"reference\":\"7f1a2c3d-aaaa-4bbb-8ccc-dddddddddddd\"}";
    assertThat(failure(503, body).reference()).isEqualTo("7f1a2c3d-aaaa-4bbb-8ccc-dddddddddddd");
    assertThat(failure(503, "{\"code\":\"ACCOUNT_STORAGE_UNAVAILABLE\"}").reference()).isNull();
    // Shorter than four characters, or with another character in it, is not a reference.
    assertThat(failure(503, "{\"reference\":\"abc\"}").reference()).isNull();
    assertThat(failure(503, "{\"reference\":\"not a reference\"}").reference()).isNull();
    assertThat(failure(200, body).reference()).isNull();
  }

  @Test
  void onlyTheFirst4096CharactersOfAFailureAnswerAreKeptThroughTheWriterAndThroughTheStream()
      throws Exception {
    assertThat(RequestStatusReason.LIMIT).isEqualTo(4096);
    String code = "{\"code\":\"IN_TIME\"}";
    String filler = "x".repeat(RequestStatusReason.LIMIT - code.length());
    assertThat(failure(409, filler + code).reason().code()).isEqualTo("IN_TIME");
    // Two characters more and the code's closing quote is past the limit.
    assertThat(failure(409, filler + "xx" + code).reason().code()).isEqualTo("HTTP_409");
    // The same through the output stream: as one array, as a part of an array, and byte by byte.
    var whole = new RequestStatusReason(new MockHttpServletResponse());
    whole.setStatus(409);
    whole.getOutputStream().write((filler + code).getBytes(StandardCharsets.UTF_8));
    assertThat(whole.reason().code()).isEqualTo("IN_TIME");
    var late = new MockHttpServletResponse();
    var cut = new RequestStatusReason(late);
    cut.setStatus(409);
    cut.getOutputStream()
        .write(
            ("xx" + filler + code).getBytes(StandardCharsets.UTF_8),
            0,
            2 + filler.length() + code.length());
    for (byte b : "{\"code\":\"TOO_LATE\"}".getBytes(StandardCharsets.UTF_8))
      cut.getOutputStream().write(b);
    assertThat(cut.reason().code()).isEqualTo("HTTP_409");
    // Whatever is kept, everything is still written to the real answer.
    assertThat(late.getContentAsString())
        .isEqualTo("xx" + filler + code + "{\"code\":\"TOO_LATE\"}");
    var single = new RequestStatusReason(new MockHttpServletResponse());
    single.setStatus(404);
    for (byte b : "{\"code\":\"NO_SUCH_PLAN\"}".getBytes(StandardCharsets.UTF_8))
      single.getOutputStream().write(b);
    assertThat(single.reason())
        .isEqualTo(
            new RequestStatusReason.Reason(
                "NO_SUCH_PLAN", "Not found: no such page, record or route"));
  }

  @Test
  void theWriterAndTheStreamAreEachMadeOnceAndFlushBufferFlushesWhatTheWriterHolds()
      throws Exception {
    assertThat(watched.getWriter()).isSameAs(watched.getWriter());
    watched.getWriter().write("partial page");
    watched.flushBuffer();
    assertThat(answer.getContentAsString()).isEqualTo("partial page");
    assertThat(answer.isCommitted()).isTrue();
    var streamed = new RequestStatusReason(new MockHttpServletResponse());
    assertThat(streamed.getOutputStream()).isSameAs(streamed.getOutputStream());
    // Flushing an answer nobody wrote to is still passed on.
    var untouched = new MockHttpServletResponse();
    new RequestStatusReason(untouched).flushBuffer();
    assertThat(untouched.isCommitted()).isTrue();
  }

  @Test
  void aStatusIsDescribedInWordsAndTextIsMaskedAndCut() {
    assertThat(RequestStatusReason.describe(429))
        .isEqualTo("Too many requests: a rate limit was reached");
    assertThat(RequestStatusReason.describe(504))
        .isEqualTo("Gateway timeout: a service behind this one did not answer in time");
    assertThat(RequestStatusReason.describe(402)).isEqualTo("HTTP 402");
    assertThat(
            RequestStatusReason.mask(
                "Too many tries for priya@example.invalid and arjun.rao@mail.example.invalid."))
        .isEqualTo("Too many tries for [email] and [email].");
    assertThat(RequestStatusReason.mask("no address here")).isEqualTo("no address here");
    assertThat(RequestStatusReason.mask("a".repeat(300))).isEqualTo("a".repeat(300));
    assertThat(RequestStatusReason.mask("a".repeat(301))).isEqualTo("a".repeat(300) + "…");
  }

  /**
   * Moved line for line from RequestLogTest (DLV-1015): the two cases that assert only what the
   * wrapper keeps and passes on, seen through the request filter that owns it and its summary line.
   * The fixture is a copy of that class's.
   */
  @Nested
  class ThroughRequestLog {
    private final ListAppender<ILoggingEvent> capture = new ListAppender<>();
    private final Logger requests = (Logger) LoggerFactory.getLogger("lookahead.http");
    private final Logger failures = (Logger) LoggerFactory.getLogger(RequestLog.class);
    private final Logger upstream = (Logger) LoggerFactory.getLogger("lookahead.upstream");

    @BeforeEach
    void listen() {
      capture.start();
      for (Logger logger : List.of(requests, failures, upstream)) logger.addAppender(capture);
    }

    @AfterEach
    void stop() {
      for (Logger logger : List.of(requests, failures, upstream)) logger.detachAppender(capture);
      capture.stop();
      MDC.clear();
    }

    private static MockHttpServletResponse run(MockHttpServletRequest request, FilterChain chain)
        throws Exception {
      var response = new MockHttpServletResponse();
      new RequestLog().doFilter(request, response, chain);
      return response;
    }

    @Test
    void successfulAnswersAreNeverCopiedAndAnErrorBodyIsReadOnlyUpToTheLimit() throws Exception {
      var big = "x".repeat(10_000);
      run(
          new MockHttpServletRequest("GET", "/learn"),
          (req, res) -> res.getWriter().write("{\"code\":\"NOT_AN_ERROR\"}" + big));
      run(
          new MockHttpServletRequest("GET", "/bff/api/v1/plans"),
          (req, res) -> {
            ((HttpServletResponse) res).setStatus(409);
            res.getWriter().write(big + "{\"code\":\"TOO_LATE\"}");
            res.flushBuffer();
          });
      assertThat(capture.list.getFirst().getFormattedMessage()).doesNotContain("NOT_AN_ERROR");
      assertThat(capture.list.getLast().getFormattedMessage())
          .contains("409 HTTP_409: Conflict with the current state")
          .doesNotContain("TOO_LATE");
      assertThat(RequestStatusReason.describe(418)).isEqualTo("HTTP 418");
      assertThat(RequestStatusReason.mask("a".repeat(400))).hasSize(301);
    }

    @Test
    void theWrapperStillWritesEverythingThroughUnchanged() throws Exception {
      var response =
          run(
              new MockHttpServletRequest("GET", "/bff/api/v1/x"),
              (req, res) -> {
                ((HttpServletResponse) res).setStatus(404);
                res.getOutputStream().write('{');
                res.getOutputStream()
                    .write("\"code\":\"NO_SUCH_PLAN\"}".getBytes(StandardCharsets.UTF_8), 0, 22);
                res.getOutputStream().flush();
                assertThat(res.getOutputStream().isReady()).isTrue();
              });
      assertThat(response.getContentAsString()).isEqualTo("{\"code\":\"NO_SUCH_PLAN\"}");
      assertThat(capture.list.getLast().getFormattedMessage())
          .contains("404 NO_SUCH_PLAN: Not found");
    }
  }
}
