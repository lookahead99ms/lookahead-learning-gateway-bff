package com.lookahead.gateway.log;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.PatternLayout;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.LoggerFactory;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.io.ClassPathResource;

/** DLV-969: captures the named loggers at DEBUG for one test; restores them on close. */
public final class LogCapture implements AutoCloseable {
  public final ListAppender<ILoggingEvent> appender = new ListAppender<>();
  private final Map<Logger, Level> levels = new LinkedHashMap<>();

  public LogCapture(String... names) {
    appender.start();
    for (String name : names) {
      var logger = (Logger) LoggerFactory.getLogger(name);
      levels.put(logger, logger.getLevel());
      logger.setLevel(Level.DEBUG);
      logger.addAppender(appender);
    }
  }

  public List<ILoggingEvent> lines() {
    return appender.list;
  }

  public List<String> messages() {
    return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
  }

  public ILoggingEvent last() {
    return appender.list.getLast();
  }

  public void clear() {
    appender.list.clear();
  }

  public static List<String> pairs(ILoggingEvent line) {
    return line.getKeyValuePairs() == null
        ? List.of()
        : line.getKeyValuePairs().stream().map(pair -> pair.key + "=" + pair.value).toList();
  }

  /**
   * Every captured message and key value is free of each {@code secret}; and never at ERROR (the
   * deploy fails on it).
   */
  public void assertNothing(String... secrets) {
    var text = new ArrayList<String>();
    for (var line : appender.list) {
      assertThat(line.getLevel()).isNotEqualTo(Level.ERROR);
      text.add(line.getFormattedMessage());
      text.addAll(pairs(line));
    }
    for (String part : text) {
      assertThat(part).doesNotContain("ERROR");
      for (String secret : secrets) assertThat(part).doesNotContain(secret);
    }
  }

  /**
   * The one console pattern every profile uses, read from the real {@code application.yml} ({@code
   * logging.pattern.console}).
   */
  public static String consolePattern() {
    try {
      for (var source :
          new YamlPropertySourceLoader()
              .load("application", new ClassPathResource("application.yml"))) {
        Object pattern = source.getProperty("logging.pattern.console");
        if (pattern != null) return pattern.toString();
      }
    } catch (IOException unreadable) {
      throw new IllegalStateException(unreadable);
    }
    throw new IllegalStateException("application.yml sets no logging.pattern.console");
  }

  /**
   * Renders a captured event exactly as the console would, through the real pattern, at the given
   * instant: the timestamp, the level, the sentence, the request bracket when the event's MDC holds
   * a requestId, and the stack trace on the lines after it when the event carries an exception.
   */
  public static String plain(ILoggingEvent event, Instant at) {
    var layout = new PatternLayout();
    layout.setContext((LoggerContext) LoggerFactory.getILoggerFactory());
    layout.setPattern(consolePattern());
    layout.start();
    try {
      if (event instanceof LoggingEvent stamped) stamped.setTimeStamp(at.toEpochMilli());
      return layout.doLayout(event);
    } finally {
      layout.stop();
    }
  }

  @Override
  public void close() {
    levels.forEach((logger, level) -> {
      logger.detachAppender(appender);
      logger.setLevel(level);
    });
    appender.stop();
  }
}
