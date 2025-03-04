package netzbegruenung.keycloak.authenticator.twofactor;

import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.validation.Validation;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.util.HashMap;
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
        String clientId = context.getAuthenticationSession().getClient().getClientId();
        UserModel authenticatedUser = context.getAuthenticationSession().getAuthenticatedUser();
        UserModel contextUser = context.getUser();
        List<String> promptParam = context.getUriInfo().getQueryParameters().get("prompt");

        logger.infof("2FA Authenticate called for client %s. Context user: %s, Session user: %s, Prompt: %s", 
            clientId,
            contextUser != null ? contextUser.getUsername() : "null",
            authenticatedUser != null ? authenticatedUser.getUsername() : "null",
            promptParam);

        // Check if this is a prompt=none request
        if (promptParam != null && promptParam.contains("none")) {
            logger.info("Prompt=none request detected in 2FA authenticator, attempting to use existing session");
            context.getSession().sessions().getUserSessionsStream(context.getRealm(), context.getAuthenticationSession().getClient())
                .findFirst()
                .ifPresent(userSession -> {
                    UserModel user = userSession.getUser();
                    if (user != null) {
                        logger.infof("Found existing session for user %s in 2FA authenticator, setting user and completing", user.getUsername());
                        context.setUser(user);
                        context.success();
                        return;
                    }
                });
        }

        // If user is already authenticated, just success
        if (contextUser != null && authenticatedUser != null) {
            logger.infof("User %s is already authenticated for client %s, skipping 2FA auth", 
                authenticatedUser.getUsername(), clientId);
            context.success();
            return;
        }

        String loginAttempt = context.getAuthenticationSession().getAuthNote("LOGIN_ATTEMPT");
        if (loginAttempt == null || !loginAttempt.equals("COMPLETED")) {
            // First phase: Show username/password form
            Map<String, String> loginData = new HashMap<>();
            loginData.put("username", "");
            loginData.put("password", "");
            
            Response challenge = context.form()
                .setAttribute("realm", context.getRealm())
                .setAttribute("auth", new LoginBean())
                .setAttribute("login", loginData)
                .setAttribute("message", new MessageBean())
                .setAttribute("url", new UrlBean(context.getUriInfo()))
                .setAttribute("client", context.getAuthenticationSession().getClient())
                .createForm("login.ftl");
            context.challenge(challenge);
            return;
        }

        // Second phase: Handle SMS verification
        String mobileNumber = context.getUser().getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE);
        if (mobileNumber == null || mobileNumber.trim().isEmpty()) {
            // Show mobile number form directly instead of adding required action
            Response challenge = context.form()
                .createForm("mobile_number_form.ftl");
            context.challenge(challenge);
            return;
        }

        // Generate and send SMS code
        String code = generateCode();
        storeCode(context, code);
        try {
            SmsServiceFactory.get(config).send(mobileNumber, "Your verification code is: " + code);
            logger.infof("SMS code sent to user %s at %s", context.getUser().getUsername(), mobileNumber);
            Response challenge = context.form()
                .setAttribute("username", context.getUser().getUsername())
                .createForm(TPL_CODE);
            context.challenge(challenge);
        } catch (Exception e) {
            logger.errorf(e, "Failed to send SMS to %s: %s", mobileNumber, e.getMessage());
            Response challenge = context.form()
                .setError("smsSendError", e.getMessage())
                .createForm("mobile-number-error.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }

        // Handle mobile number submission
        String mobileNumber = formData.getFirst(MOBILE_NUMBER_FIELD);
        if (mobileNumber != null) {
            if (mobileNumber.trim().isEmpty()) {
                Response challenge = context.form()
                    .setError("missingMobileNumber")
                    .createForm("mobile_number_form.ftl");
                context.challenge(challenge);
                return;
            }

            // Store the mobile number
            context.getUser().setSingleAttribute(MOBILE_NUMBER_ATTRIBUTE, mobileNumber);
            
            // Now proceed with SMS verification
            authenticate(context);
            return;
        }

        if (!validateForm(context, formData)) {
            Map<String, String> loginData = new HashMap<>();
            loginData.put("username", formData.getFirst("username"));
            loginData.put("password", "");
            
            Response challenge = context.form()
                .setAttribute("realm", context.getRealm())
                .setAttribute("auth", new LoginBean())
                .setAttribute("login", loginData)
                .setAttribute("message", new MessageBean())
                .setAttribute("url", new UrlBean(context.getUriInfo()))
                .setAttribute("client", context.getAuthenticationSession().getClient())
                .setError("Invalid username or password")
                .createForm("login.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }

        if (context.getUser() == null) {
            // Handle username/password form submission
            String username = formData.getFirst("username");
            String password = formData.getFirst("password");
            
            try {
                UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);
                logger.infof("Found user for username %s: %s", username, user != null);
                if (user != null) {
                    // Get password provider
                    PasswordCredentialProvider passwordProvider = (PasswordCredentialProvider) context.getSession()
                        .getProvider(CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);
                    logger.infof("Got password provider: %s", passwordProvider != null);
                    
                    // Create credential input
                    UserCredentialModel credentialInput = UserCredentialModel.password(password);
                    
                    // Validate password
                    boolean isValid = passwordProvider.isValid(context.getRealm(), user, credentialInput);
                    logger.infof("Password validation result for user %s: %s", username, isValid);
                    
                    if (isValid) {
                        context.setUser(user);
                        // Mark login attempt as completed
                        context.getAuthenticationSession().setAuthNote("LOGIN_ATTEMPT", "COMPLETED");
                        // Now proceed with SMS verification
                        authenticate(context);
                        return;
                    }
                }
            } catch (Exception e) {
                logger.error("Error validating credentials", e);
            }

            // If we get here, validation failed
            Map<String, String> loginData = new HashMap<>();
            loginData.put("username", username != null ? username : "");
            loginData.put("password", "");
            
            Response challenge = context.form()
                .setAttribute("realm", context.getRealm())
                .setAttribute("auth", new LoginBean())
                .setAttribute("login", loginData)
                .setAttribute("message", new MessageBean())
                .setAttribute("url", new UrlBean(context.getUriInfo()))
                .setAttribute("client", context.getAuthenticationSession().getClient())
                .setError("Invalid username or password")
                .createForm("login.ftl");
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            return;
        }

        // Handle SMS code validation
        String enteredCode = formData.getFirst("code");
        String expectedCode = context.getAuthenticationSession().getAuthNote("code");

        if (expectedCode != null && expectedCode.equals(enteredCode)) {
            logger.infof("Successful 2FA verification for user %s", context.getUser().getUsername());
            context.success();
        } else {
            logger.warnf("Invalid 2FA code entered for user %s", context.getUser().getUsername());
            Response challenge = context.form()
                .setAttribute("username", context.getUser().getUsername())
                .setError("invalidCode")
                .createForm(TPL_CODE);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
        }
    }

    private boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        logger.infof("Validating form data: %s", formData);
        if (context.getUser() != null) {
            // If we already have a user, we're in SMS verification phase
            return true;
        }
        
        String username = formData.getFirst("username");
        String password = formData.getFirst("password");
        
        logger.infof("Validating username/password. Username present: %s, Password present: %s", 
            username != null, password != null);
            
        return username != null && !username.isEmpty() &&
               password != null && !password.isEmpty();
    }

    private String generateCode() {
        return SecretGenerator.getInstance().randomString(6, SecretGenerator.DIGITS);
    }

    private void storeCode(AuthenticationFlowContext context, String code) {
        context.getAuthenticationSession().setAuthNote("code", code);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        String mobileNumber = user.getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE);
        return mobileNumber != null && !mobileNumber.trim().isEmpty();
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Do not add required actions during authentication flow
    }

    @Override
    public void close() {
        // Nothing to close
    }
}
