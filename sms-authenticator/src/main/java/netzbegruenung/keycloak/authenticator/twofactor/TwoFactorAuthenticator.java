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
import java.util.HashMap;

public class TwoFactorAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(TwoFactorAuthenticator.class);
    private static final String TPL_CODE = "login-sms.ftl";
    private static final String MOBILE_NUMBER_ATTRIBUTE = "mobile_number";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null || config.getConfig() == null) {
            logger.error("SMS authenticator config not found");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                context.form().setError("smsAuthConfigError").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            return;
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
            int length = Integer.parseInt(config.getConfig().getOrDefault("length", "6"));
            int ttl = Integer.parseInt(config.getConfig().getOrDefault("ttl", "300"));

            String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            authSession.setAuthNote("code", code);
            authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

            Theme theme = context.getSession().theme().getTheme(Theme.Type.LOGIN);
            Locale locale = context.getSession().getContext().resolveLocale(user);
            String smsAuthText = theme.getEnhancedMessages(context.getRealm(), locale).getProperty("smsAuthText", "Your SMS code is: %1$s");
            String smsText = String.format(smsAuthText, code);

            SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);

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
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String code = authSession.getAuthNote("code");
        String ttl = authSession.getAuthNote("ttl");

        if (code == null || ttl == null) {
            logger.error("No code or TTL found in auth session");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                context.form().setError("smsAuthInternalError").createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            return;
        }

        String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");
        if (enteredCode == null || enteredCode.trim().isEmpty()) {
            logger.warn("No code entered by user");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                context.form().setAttribute("realm", context.getRealm())
                    .setError("smsAuthCodeMissing").createForm(TPL_CODE));
            return;
        }

        boolean isValid = enteredCode.equals(code);
        if (isValid) {
            long expirationTime = Long.parseLong(ttl);
            if (System.currentTimeMillis() > expirationTime) {
                logger.warn("Code expired");
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                    context.form().setError("smsAuthCodeExpired").createForm(TPL_CODE));
            } else {
                context.success();
            }
        } else {
            AuthenticationExecutionModel execution = context.getExecution();
            if (execution.isRequired()) {
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setAttribute("realm", context.getRealm())
                        .setError("smsAuthCodeInvalid").createForm(TPL_CODE));
            } else if (execution.isConditional() || execution.isAlternative()) {
                context.attempted();
            }
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // Always return false so that we can handle the setup flow
        return false;
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
