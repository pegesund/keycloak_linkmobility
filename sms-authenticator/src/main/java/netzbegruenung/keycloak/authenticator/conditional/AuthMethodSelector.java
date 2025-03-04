package netzbegruenung.keycloak.authenticator.conditional;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
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
            for (AuthMethod method : AuthMethod.values()) {
                if (method.value.equalsIgnoreCase(text)) {
                    return method;
                }
            }
            return SMS; // Default to SMS
        }

        public String getValue() {
            return value;
        }
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UriInfo uriInfo = context.getUriInfo();
        String requestUri = uriInfo.getRequestUri().toString();
        String referrer = context.getHttpRequest().getHttpHeaders().getHeaderString("Referer");
        List<String> authParam = uriInfo.getQueryParameters().get("auth");
        List<String> promptParam = uriInfo.getQueryParameters().get("prompt");
        String clientId = context.getAuthenticationSession().getClient().getClientId();
        
        logger.infof("Starting authentication with URI: %s, Referrer: %s, Client ID: %s, Prompt: %s", 
            requestUri, referrer, clientId, promptParam);

        // Check if this is a prompt=none request
        if (promptParam != null && promptParam.contains("none")) {
            logger.info("Prompt=none request detected, attempting to use existing session");
            context.getSession().sessions().getUserSessionsStream(context.getRealm(), context.getAuthenticationSession().getClient())
                .findFirst()
                .ifPresent(userSession -> {
                    UserModel user = userSession.getUser();
                    if (user != null) {
                        logger.infof("Found existing session for user %s, setting user and completing auth", user.getUsername());
                        context.setUser(user);
                        context.success();
                        return;
                    }
                });
        }

        // If user is already authenticated, just success
        UserModel authenticatedUser = context.getAuthenticationSession().getAuthenticatedUser();
        if (context.getUser() != null && authenticatedUser != null) {
            logger.infof("User %s is already authenticated for client %s, skipping auth method selection", 
                authenticatedUser.getUsername(), clientId);
            context.success();
            return;
        }
        
        // Get requested auth method from URL parameter
        AuthMethod requestedMethod = AuthMethod.SMS; // Default to SMS
        if (authParam != null && !authParam.isEmpty()) {
            requestedMethod = AuthMethod.fromString(authParam.get(0));
            logger.infof("Auth parameter found: %s, mapped to method: %s", authParam.get(0), requestedMethod.name());
        }
        
        // Also check the referrer URL for specific paths
        if (referrer != null) {
            if (referrer.contains("/sms-auth") || referrer.contains("/auth/sms")) {
                requestedMethod = AuthMethod.SMS;
            } else if (referrer.contains("/2fa") || referrer.contains("/auth/2fa")) {
                requestedMethod = AuthMethod.TWO_FACTOR;
            }
        }

        // Store the selected method for the flow configuration
        context.getAuthenticationSession().setAuthNote("SELECTED_AUTH_METHOD", requestedMethod.getValue());

        // Get configuration from context
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        Map<String, String> config = configModel != null ? configModel.getConfig() : null;
        
        // Create and route to the selected authenticator
        Authenticator authenticator = requestedMethod.createAuthenticator(config);
        authenticator.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Get the selected auth method from the session
        String selectedMethod = context.getAuthenticationSession().getAuthNote("SELECTED_AUTH_METHOD");
        AuthMethod method = AuthMethod.fromString(selectedMethod);
        
        // Get configuration from context
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        Map<String, String> config = configModel != null ? configModel.getConfig() : null;
        
        // Create and route the action to the selected authenticator
        Authenticator authenticator = method.createAuthenticator(config);
        authenticator.action(context);
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
        // Not needed
    }

    @Override
    public void close() {
        // Nothing to close
    }
}
