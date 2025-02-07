package netzbegruenung.keycloak.authenticator.smsonly;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.UserProvider;
import netzbegruenung.keycloak.authenticator.gateway.SmsService;
import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;

import jakarta.ws.rs.core.Response;
import java.util.Random;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class SmsOnlyAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(SmsOnlyAuthenticator.class);
    private static final String TPL_PHONE = "login-sms-phone.ftl";
    private static final String TPL_CODE = "login-sms-only.ftl";
    private static final String MOBILE_NUMBER_ATTRIBUTE = "mobile_number";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Show phone number input form first
        Response challenge = context.form()
                .createForm(TPL_PHONE);
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String phoneNumber = context.getHttpRequest().getDecodedFormParameters().getFirst("phone_number");
        String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");
        
        if (phoneNumber != null && !phoneNumber.trim().isEmpty()) {
            // Phone number was submitted
            logger.info("Searching for user with phone number: " + phoneNumber);
            
            // Find user by phone number attribute
            UserModel user = null;
            try (Stream<UserModel> users = context.getSession().users().searchForUserByUserAttributeStream(context.getRealm(), MOBILE_NUMBER_ATTRIBUTE, phoneNumber)) {
                user = users.findFirst().orElse(null);
            }
            
            if (user == null) {
                logger.warn("No user found with phone number: " + phoneNumber);
                
                // List all users and their phone numbers for debugging
                try (Stream<UserModel> allUsers = context.getSession().users().searchForUserStream(context.getRealm(), Map.of())) {
                    allUsers.forEach(u -> {
                        String mobile = u.getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE);
                        logger.info("User " + u.getUsername() + " has mobile number: " + mobile);
                    });
                }
                
                // No user found with this phone number
                context.failureChallenge(
                    AuthenticationFlowError.INVALID_USER,
                    context.form()
                        .setError("invalidPhoneMessage", "No account found with this phone number")
                        .createForm(TPL_PHONE)
                );
                return;
            }

            logger.info("Found user: " + user.getUsername());
            
            // Store the found user in context
            context.setUser(user);
            
            // Generate and send OTP
            String code = generateCode();
            context.getAuthenticationSession().setAuthNote("sms-code", code);
            sendSms(context, phoneNumber, code);

            // Show OTP input form
            Response challenge = context.form()
                    .createForm(TPL_CODE);
            context.challenge(challenge);
            
        } else if (enteredCode != null) {
            // OTP code was submitted
            String expectedCode = context.getAuthenticationSession().getAuthNote("sms-code");
            
            if (enteredCode.equals(expectedCode)) {
                context.success();
            } else {
                context.failureChallenge(
                    AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form()
                        .addError(new FormMessage("invalidCodeMessage"))
                        .createForm(TPL_CODE)
                );
            }
        }
    }

    private String generateCode() {
        Random random = new Random();
        int code = 100000 + random.nextInt(900000); // generates 6-digit code
        return String.valueOf(code);
    }

    private void sendSms(AuthenticationFlowContext context, String phoneNumber, String code) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        SmsService smsService = SmsServiceFactory.get(config.getConfig());
        String message = String.format("Your authentication code is: %s", code);
        smsService.send(phoneNumber, message);
    }

    @Override
    public boolean requiresUser() {
        return false;  // Changed to false since we find the user by phone number
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE) != null;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Not needed for this flow
    }

    @Override
    public void close() {
        // No resources to close
    }
}
