package com.lookahead.learning.content.gateway;

import java.util.Optional;

/**
 * The sign-in the person chose on our own page (DLV-969). Cognito then skips its managed login page and goes straight
 * to that provider. Google gets {@code prompt=select_account}: Google rejects {@code prompt=login}, and the account
 * chooser lets someone switch Google accounts after signing out. Password sign-in keeps {@code prompt=login}.
 */
enum SignInProvider {
    GOOGLE("google", "Google", "select_account"),
    PASSWORD("password", "COGNITO", "login");

    static final String PARAMETER = "provider";
    final String parameter;
    final String cognitoName;
    final String prompt;

    SignInProvider(String parameter, String cognitoName, String prompt) {
        this.parameter = parameter; this.cognitoName = cognitoName; this.prompt = prompt;
    }

    /** Only the two known names; Google only while the pool has the Google provider switched on. Anything else is the default page. */
    static Optional<SignInProvider> from(String value, boolean googleEnabled) {
        if (PASSWORD.parameter.equals(value)) return Optional.of(PASSWORD);
        if (GOOGLE.parameter.equals(value) && googleEnabled) return Optional.of(GOOGLE);
        return Optional.empty();
    }

    /** {@code app.cognito.google-sign-in}: false until the Cognito Google provider exists (task variable LOOKAHEAD_GOOGLE_SIGN_IN). */
    static boolean googleEnabled(org.springframework.core.env.Environment environment) {
        return environment.getProperty("app.cognito.google-sign-in", Boolean.class, false);
    }
}
