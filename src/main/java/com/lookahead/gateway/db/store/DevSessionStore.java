package com.lookahead.gateway.db.store;

import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.util.DevSessionStatus;
import com.lookahead.gateway.util.Repeats;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;
import software.amazon.awssdk.core.retry.RetryMode;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClientBuilder;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * Reads the DEV session row of the operations table in DynamoDB and says what it means for the Web
 * shell. The SDK client is a bean of its own ({@code devSessionDynamoDb}); Spring closes it at
 * shutdown, so this class has nothing to close.
 */
public final class DevSessionStore {
  private final DynamoDbClient client;
  private final String table;
  private final Repeats invalidDeadline = new Repeats(Duration.ofMinutes(1));

  public DevSessionStore(DynamoDbClient client, String table) {
    this.client = client;
    this.table = table;
  }

  /** The attributes of the row with id {@code dev}; empty when the row does not exist. */
  public Map<String, AttributeValue> read() {
    return OpsLog.aws(
            "dynamodb",
            "GetItem",
            "table " + table,
            true,
            () ->
                client.getItem(r ->
                    r.tableName(table)
                        .consistentRead(true)
                        .key(Map.of("id", AttributeValue.builder().s("dev").build()))))
        .item();
  }

  /**
   * The status the route answers with, or null when it cannot be given: the table could not be
   * read, or its deadline is not an instant. Each of the two is logged here, where it happens; the
   * route answers 503 for both.
   */
  public DevSessionStatus status() {
    try {
      // Polled by the Web shell: a successful read logs at DEBUG; a failure, a refusal and every
      // retry at WARN/INFO.
      var state = read();
      String deadline = state.containsKey("deadline") ? state.get("deadline").s() : "";
      boolean warning;
      try {
        warning =
            !deadline.isEmpty()
                && !Instant.now().isBefore(Instant.parse(deadline).minusSeconds(900));
      } catch (DateTimeParseException invalid) {
        // DLV-969: the table answered, but its deadline is not an instant; polled, so once a minute
        // while it stays so.
        if (invalidDeadline.due("DEV_STATUS_INVALID"))
          OpsLog.failed("dev-session.status", "DEV_STATUS_INVALID")
              .log(
                  "DEV session status unavailable: DEV_STATUS_INVALID (the operations table's"
                      + " deadline attribute is not an ISO-8601 instant); logged at most once a"
                      + " minute");
        return null;
      }
      invalidDeadline.clear();
      return new DevSessionStatus(deadline, warning, state.containsKey("operation"));
    } catch (RuntimeException unavailable) {
      OpsLog.failed("dev-session.status", "DEV_STATUS_UNAVAILABLE")
          .addKeyValue("exception.types", OpsLog.types(unavailable))
          .log(
              "DEV session status unavailable: DEV_STATUS_UNAVAILABLE (the operations table could"
                  + " not be read: {}); answered 503",
              OpsLog.types(unavailable));
      return null;
    }
  }

  /**
   * The SDK's standard retry mode: at most this many attempts per read, each one logged after the
   * first (DLV-969).
   */
  static final int MAX_ATTEMPTS = 3;

  /**
   * Timeouts, the standard retry mode (3 attempts, stated so the log can say "attempt 2 of 3") and
   * the retry log line.
   */
  public static DynamoDbClientBuilder configured(DynamoDbClientBuilder builder) {
    return builder
        .httpClientBuilder(
            UrlConnectionHttpClient.builder()
                .connectionTimeout(Duration.ofSeconds(2))
                .socketTimeout(Duration.ofSeconds(3)))
        .overrideConfiguration(c ->
            c.apiCallTimeout(Duration.ofSeconds(4))
                .apiCallAttemptTimeout(Duration.ofSeconds(3))
                .retryStrategy(RetryMode.STANDARD)
                .addExecutionInterceptor(new OpsLog.SdkRetries("dynamodb", MAX_ATTEMPTS)));
  }
}
