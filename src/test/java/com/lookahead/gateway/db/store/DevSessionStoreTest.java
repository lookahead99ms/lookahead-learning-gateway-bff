package com.lookahead.gateway.db.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import com.lookahead.gateway.controller.DevSessionStatusController;
import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.util.DevSessionStatus;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;

/**
 * DLV-1015: the read of the DEV session row and what it means (the deadline, the warning and the maintenance flag moved
 * here from DevSessionStatusController.status, statements unchanged, with their two log lines).
 */
@SuppressWarnings("unchecked")
class DevSessionStoreTest {
    private final DynamoDbClient sdk = mock(DynamoDbClient.class);
    private final DevSessionStore store = new DevSessionStore(sdk, "synthetic-operations");

    private static AttributeValue text(String value) { return AttributeValue.builder().s(value).build(); }
    private void row(Map<String, AttributeValue> item) {
        when(sdk.getItem(any(Consumer.class))).thenReturn(GetItemResponse.builder().item(item).build());
    }

    @Test void readAsksForTheDevRowOfTheTableWithAConsistentReadAndReturnsItsAttributes() {
        var item = Map.of("id", text("dev"), "deadline", text("2999-01-01T00:00:00Z"));
        row(item);
        assertThat(store.read()).isEqualTo(item);
        ArgumentCaptor<Consumer<GetItemRequest.Builder>> asked = ArgumentCaptor.forClass(Consumer.class);
        verify(sdk, times(1)).getItem(asked.capture());
        var request = GetItemRequest.builder();
        asked.getValue().accept(request);
        assertThat(request.build()).isEqualTo(GetItemRequest.builder().tableName("synthetic-operations").consistentRead(true).key(Map.of("id", text("dev"))).build());
        // A row that does not exist is an empty map, never null.
        when(sdk.getItem(any(Consumer.class))).thenReturn(GetItemResponse.builder().build());
        assertThat(store.read()).isEmpty();
        verify(sdk, never()).close();
    }

    @Test void statusGivesTheStoredDeadlineTheWarningInTheLastFifteenMinutesAndTheMaintenanceFlag() {
        try (var log = new LogCapture("lookahead.event")) {
            row(Map.of());
            assertThat(store.status()).isEqualTo(new DevSessionStatus("", false, false));
            String far = Instant.now().plusSeconds(3600).toString(), near = Instant.now().plusSeconds(899).toString(), past = Instant.now().minusSeconds(5).toString();
            row(Map.of("deadline", text(far)));
            assertThat(store.status()).isEqualTo(new DevSessionStatus(far, false, false));
            row(Map.of("deadline", text(near)));
            assertThat(store.status()).isEqualTo(new DevSessionStatus(near, true, false));
            row(Map.of("deadline", text(past), "operation", text("private-operation-id")));
            assertThat(store.status()).isEqualTo(new DevSessionStatus(past, true, true));
            row(Map.of("operation", text("private-operation-id")));
            assertThat(store.status()).isEqualTo(new DevSessionStatus("", false, true));
            // Polled by the Web shell: a good read writes nothing above DEBUG.
            assertThat(log.lines()).allMatch(line -> line.getLevel() == Level.DEBUG);
        }
    }

    @Test void aDeadlineThatIsNotAnInstantGivesNoStatusAndOneWarnLineAtMostOnceAMinute() {
        try (var log = new LogCapture("lookahead.event")) {
            var bad = text("tomorrow-synthetic-secret");
            var answers = new ArrayDeque<>(List.of(bad, bad, text(Instant.now().plusSeconds(3600).toString()), bad));
            when(sdk.getItem(any(Consumer.class))).thenAnswer(call -> GetItemResponse.builder().item(Map.of("deadline", answers.poll())).build());
            assertThat(store.status()).isNull();
            var warnings = (Supplier<List<ILoggingEvent>>)
                    () -> log.lines().stream().filter(line -> line.getLevel() != Level.DEBUG).toList();
            assertThat(warnings.get()).hasSize(1);
            var line = warnings.get().get(0);
            assertThat(line.getLevel()).isEqualTo(Level.WARN);
            assertThat(line.getFormattedMessage()).isEqualTo("DEV session status unavailable: DEV_STATUS_INVALID (the operations table's deadline attribute is "
                    + "not an ISO-8601 instant); logged at most once a minute");
            assertThat(LogCapture.pairs(line)).contains("event.action=dev-session.status", "event.outcome=failure", "reason=DEV_STATUS_INVALID");
            assertThat(store.status()).isNull();                 // the same problem within the minute: quiet
            assertThat(warnings.get()).hasSize(1);
            assertThat(store.status()).isNotNull();              // recovered
            assertThat(store.status()).isNull();                 // fails again: logged at once
            assertThat(warnings.get()).hasSize(2);
            log.assertNothing("synthetic-secret");
        }
    }

    @Test void aTableThatCannotBeReadOrARowOfAnotherShapeGivesNoStatusAndOneWarnLineEachTime() {
        try (var log = new LogCapture("lookahead.event")) {
            when(sdk.getItem(any(Consumer.class))).thenThrow(SdkClientException.create("Unable to execute HTTP request: connection reset"));
            for (int attempt = 1; attempt <= 2; attempt++) {
                log.clear();
                assertThat(store.status()).isNull();
                assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
                assertThat(log.last().getFormattedMessage())
                        .isEqualTo("DEV session status unavailable: DEV_STATUS_UNAVAILABLE (the operations table could not be read: SdkClientException); answered 503");
                assertThat(LogCapture.pairs(log.last())).contains("event.action=dev-session.status", "event.outcome=failure", "reason=DEV_STATUS_UNAVAILABLE",
                        "exception.types=SdkClientException");
            }
        }
        // A deadline attribute that is not a string is reported the same way (the row could not be used).
        var other = mock(DynamoDbClient.class);
        when(other.getItem(any(Consumer.class))).thenReturn(GetItemResponse.builder().item(Map.of("deadline", AttributeValue.builder().n("5").build())).build());
        try (var log = new LogCapture("lookahead.event")) {
            assertThat(new DevSessionStore(other, "synthetic-operations").status()).isNull();
            assertThat(log.last().getFormattedMessage())
                    .isEqualTo("DEV session status unavailable: DEV_STATUS_UNAVAILABLE (the operations table could not be read: NullPointerException); answered 503");
        }
    }

    /**
     * DLV-969 (owner, 2026-11-04): each fallback that used to answer 502 or 503 without a word now writes one WARN line with
     * what was being done and why: a stable reason code, the upstream status and exception types. Never a body or a token.
     */
    @Nested class FallbackReason {
    static final String SECRET = "synthetic-body-secret";
    static final String TOKEN = "synthetic-server-token";
    final LogCapture log = new LogCapture("lookahead.event");

    @AfterEach void close() { log.close(); }

    void reason(String action, String reason) {
        assertThat(log.lines()).isNotEmpty();
        assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
        assertThat(LogCapture.pairs(log.last())).contains("event.action=" + action, "reason=" + reason);
        log.assertNothing(SECRET, TOKEN);
    }

    @Test void aMalformedDevDeadlineIsNamedAndLoggedAtMostOnceAMinute() {
        var client = mock(DynamoDbClient.class);
        var bad = AttributeValue.builder().s("tomorrow-" + SECRET).build();
        var good = AttributeValue.builder().s(Instant.now().plusSeconds(3600).toString()).build();
        var answers = new ArrayDeque<>(List.of(bad, bad, good, bad));
        Mockito.when(client.getItem(any(Consumer.class))).thenAnswer(call ->
                GetItemResponse.builder().item(Map.of("deadline", answers.poll())).build());
        var status = new DevSessionStatusController(new DevSessionStore(client, "state"));
        assertThat(status.status().getStatusCode().value()).isEqualTo(503);
        reason("dev-session.status", "DEV_STATUS_INVALID");
        assertThat(status.status().getStatusCode().value()).isEqualTo(503);  // same problem within the minute: quiet
        assertThat(log.lines()).hasSize(1);
        assertThat(status.status().getStatusCode().value()).isEqualTo(200);  // recovered
        assertThat(status.status().getBody()).containsEntry("code", "DEV_STATUS_UNAVAILABLE");  // fails again: logged at once
        assertThat(log.lines()).hasSize(2);
        assertThat(log.last().getFormattedMessage()).contains("deadline attribute is not an ISO-8601 instant");
    }
    }
}
