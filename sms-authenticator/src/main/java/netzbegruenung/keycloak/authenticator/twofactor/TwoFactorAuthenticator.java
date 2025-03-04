package netzbegruenung.keycloak.authenticator.twofactor;

import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.*;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class TwoFactorAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(TwoFactorAuthenticator.class);
    private static final String TPL_CODE = "login-sms.ftl";
    private static final String MOBILE_NUMBER_ATTRIBUTE = "mobile_number";
    private static final String MOBILE_NUMBER_FIELD = "mobile_number";
    private Map<String, String> config;

    public TwoFactorAuthenticator(Map<String, String> config) {
        this.config = config;
    }

    public TwoFactorAuthenticator() {
        // Default constructor for service loading
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();
        if (authConfig == null || authConfig.getConfig() == null) {
            logger.error("SMS authenticator config not found");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                context.form().setError("smsAuthConfigError").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            return;
        }

        if (config == null) {
            config = authConfig.getConfig();
        }

        UserModel user = context.getUser();
        String mobileNumber = user.getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE);
        
        // If no mobile number, add required action and challenge
        if (mobileNumber == null || mobileNumber.trim().isEmpty()) {
            logger.info("No mobile number found for user: " + user.getUsername() + ", adding required action");
            user.addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
            Response challenge = context.form()
                .createForm("mobile_number_form.ftl");
            context.challenge(challenge);
            return;
        }

        // Always send SMS code for 2FA
        try {
            int length = Integer.parseInt(config.getOrDefault("length", "6"));
            int ttl = Integer.parseInt(config.getOrDefault("ttl", "300"));

            String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            authSession.setAuthNote("code", code);
            authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

            Theme theme = context.getSession().theme().getTheme(Theme.Type.LOGIN);
            Locale locale = context.getSession().getContext().resolveLocale(user);
            String smsAuthText = theme.getEnhancedMessages(context.getRealm(), locale).getProperty("smsAuthText", "Your SMS code is %1$s and is valid for %2$d minutes.");
            String smsText = String.format(smsAuthText, code, ttl/60);

            SmsServiceFactory.get(config).send(mobileNumber, smsText);

            Response challenge = context.form()
                .setAttribute("realm", context.getRealm())
                .setAttribute("mobile_number", mobileNumber)
                .createForm(TPL_CODE);
            context.challenge(challenge);
        } catch (Exception e) {
            logger.error("Failed to send SMS", e);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                context.form().setError("smsAuthSmsError").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");
        
        if (enteredCode == null || enteredCode.isEmpty()) {
            Response challenge = context.form()
                .setError("missingCode")
                .createForm(TPL_CODE);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String code = authSession.getAuthNote("code");
        String ttl = authSession.getAuthNote("ttl");

        if (code == null || ttl == null) {
            Response challenge = context.form()
                .setError("codeExpired")
                .createForm(TPL_CODE);
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
            return;
        }

        boolean valid = enteredCode.equals(code);
        long expirationTime = Long.parseLong(ttl);
        boolean expired = System.currentTimeMillis() > expirationTime;

        if (expired) {
            Response challenge = context.form()
                .setError("codeExpired")
                .createForm(TPL_CODE);
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
            return;
        }

        if (!valid) {
            Response challenge = context.form()
                .setError("invalidCode")
                .createForm(TPL_CODE);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }

        // Clear the code from the session
        authSession.removeAuthNote("code");
        authSession.removeAuthNote("ttl");

        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        String mobileNumber = user.getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE);
        return mobileNumber != null && !mobileNumber.trim().isEmpty();
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Only add the required action if it's not already set
        if (!user.getRequiredActionsStream().anyMatch(action -> action.equals(PhoneNumberRequiredAction.PROVIDER_ID))) {
            user.addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
        }
    }

    @Override
    public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
        return List.of();
    }

    @Override
    public void close() {
    }
}
