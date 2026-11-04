package com.lookahead.gateway.tls;

import com.lookahead.gateway.StartupLog;
import java.util.LinkedHashMap;
import java.util.List;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.Profiles;

/**
 * Runs before context refresh, SSL bundle construction and any listening server. A refused start logs which injected
 * variable could not be read or was rejected (DLV-969), by name only; the validator names its own rejections.
 */
public final class InjectedCredentials implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    @Override public void initialize(ConfigurableApplicationContext context) {
        var environment = context.getEnvironment();
        if (!environment.acceptsProfiles(Profiles.of("lower-cost-dev"))) return;
        String reading = null;
        try {
        var inputs = new LinkedHashMap<String, String>();
        for (String name : List.of("LOOKAHEAD_TLS_SCHEMA", "LOOKAHEAD_TLS_SERVER_CERTIFICATE", "LOOKAHEAD_TLS_SERVER_KEY",
                "LOOKAHEAD_TLS_TRUST", "LOOKAHEAD_TLS_SERVER_NAME", "LOOKAHEAD_TLS_CLIENT_CERTIFICATE", "LOOKAHEAD_TLS_CLIENT_KEY",
                "APP_OAUTH_CLIENT_ID", "LOOKAHEAD_GATEWAY_CLIENT_SECRET", "LOOKAHEAD_ADMISSION_CLIENT_ID",
                "LOOKAHEAD_ADMISSION_CLIENT_SECRET", "LOOKAHEAD_DOMAIN_GATEWAY_SECRET", "LOOKAHEAD_DOMAIN_DB_PASSWORD")) {
            reading = name;
            inputs.put(name, environment.getProperty(name));
        }
        reading = null;
        environment.getPropertySources().addFirst(new MapPropertySource("validatedInjectedCredentials",
                InjectedCredentialValidator.properties(inputs, "gateway")));
        } catch (Exception rejected) {
            // An unresolvable placeholder's message quotes the value; only the variable's name and the type are logged.
            if (reading != null) throw StartupLog.refused("injected credential " + reading, rejected instanceof IllegalArgumentException
                    ? "UNRESOLVED_PLACEHOLDER" : "UNREADABLE_" + rejected.getClass().getSimpleName(), InjectedCredentialValidator.REFUSED);
            throw new IllegalStateException(InjectedCredentialValidator.REFUSED);
        }
    }
}
