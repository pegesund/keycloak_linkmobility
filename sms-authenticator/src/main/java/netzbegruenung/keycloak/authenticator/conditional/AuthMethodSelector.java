package netzbegruenung.keycloak.authenticator.conditional;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;
import netzbegruenung.keycloak.authenticator.smsonly.SmsAuthenticator;
import netzbegruenung.keycloak.authenticator.twofactor.TwoFactorAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;

import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.util.List;
import java.util.Map;

public class AuthMethodSelector implements Authenticator {
    private static final Logger logger = Logger.getLogger(AuthMethodSelector.class);

    private enum AuthMethod {
        SMS("sms") {
            @Override
            public Authenticator createAuthenticator(Map<String, String> config) {
                return new SmsAuthenticator(config);
            }
        },
        TWO_FACTOR("2fa") {
            @Override
            public Authenticator createAuthenticator(Map<String, String> config) {
                return new TwoFactorAuthenticator(config);
            }
        };

        private final String value;

        AuthMethod(String value) {
            this.value = value;
        }

        public abstract Authenticator createAuthenticator(Map<String, String> config);

        public static AuthMethod fromString(String text) {
            logger.infof("Attempting to find auth method for text: '%s'", text);
            for (AuthMethod method : AuthMethod.values()) {
                logger.infof("Comparing with method value: '%s'", method.value);
                if (method.value.equalsIgnoreCase(text)) {
                    logger.infof("Found matching method: %s", method.name());
                    return method;
                }
            }
            logger.infof("No matching method found, defaulting to SMS");
            return SMS; // Default to SMS
        }

        public String getValue() {
            return value;
        }
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Get and store the auth method immediately
        AuthMethod requestedMethod = getRequestedMethod(context);
        logger.infof("Selected auth method: %s", requestedMethod.name());
        
        // Store the selected method in the session before any potential redirects
        context.getAuthenticationSession().setAuthNote("SELECTED_AUTH_METHOD", requestedMethod.getValue());
        
        // Create and delegate to the appropriate authenticator
        Authenticator authenticator = requestedMethod.createAuthenticator(
            context.getAuthenticatorConfig() != null ? context.getAuthenticatorConfig().getConfig() : null);
        logger.infof("Created authenticator of type: %s", authenticator.getClass().getSimpleName());
        authenticator.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Get the selected auth method from the session
        String method = context.getAuthenticationSession().getAuthNote("SELECTED_AUTH_METHOD");
        logger.infof("Retrieved method from session: %s", method);
        AuthMethod requestedMethod = method != null ? AuthMethod.fromString(method) : AuthMethod.SMS;
        logger.infof("Using auth method for action: %s", requestedMethod.name());
        
        // Create and delegate to the appropriate authenticator
        Authenticator authenticator = requestedMethod.createAuthenticator(
            context.getAuthenticatorConfig() != null ? context.getAuthenticatorConfig().getConfig() : null);
        authenticator.action(context);
    }

    private AuthMethod getRequestedMethod(AuthenticationFlowContext context) {
        // Check URL parameters first
        UriInfo uriInfo = context.getUriInfo();
        logger.infof("All query parameters: %s", uriInfo.getQueryParameters());
        
        // First check direct auth_method parameter
        String method = uriInfo.getQueryParameters().getFirst("auth_method");
        logger.infof("Found auth_method in URL parameters: '%s'", method);
        
        // If not found, check in redirect_uri
        if (method == null) {
            String redirectUri = uriInfo.getQueryParameters().getFirst("redirect_uri");
            if (redirectUri != null && redirectUri.contains("auth_method=")) {
                method = redirectUri.substring(redirectUri.indexOf("auth_method=") + 11);
                if (method.contains("&")) {
                    method = method.substring(0, method.indexOf("&"));
                }
                logger.infof("Found auth_method in redirect_uri: '%s'", method);
            }
        }
        
        if (method != null) {
            try {
                AuthMethod result = AuthMethod.fromString(method);
                logger.infof("Using method from URL: %s", result.name());
                return result;
            } catch (IllegalArgumentException e) {
                logger.warn("Invalid auth_method parameter: " + method);
            }
        }
        
        // Check session
        String sessionMethod = context.getAuthenticationSession().getAuthNote("SELECTED_AUTH_METHOD");
        logger.infof("Found method in session: '%s'", sessionMethod);
        if (sessionMethod != null) {
            try {
                AuthMethod result = AuthMethod.fromString(sessionMethod);
                logger.infof("Using method from session: %s", result.name());
                return result;
            } catch (IllegalArgumentException e) {
                logger.warn("Invalid auth_method in session: " + sessionMethod);
            }
        }
        
        logger.info("No method found in URL or session, defaulting to SMS");
        return AuthMethod.SMS;
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions needed
    }

    @Override
    public void close() {
        // Nothing to close
    }
}
