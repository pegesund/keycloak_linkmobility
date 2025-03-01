package netzbegruenung.keycloak.authenticator.twofactor;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

public class TwoFactorAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "sms-2fa-authenticator";
    private static final TwoFactorAuthenticator SINGLETON = new TwoFactorAuthenticator();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "SMS Two-Factor Authentication";
    }

    @Override
    public String getReferenceCategory() {
        return "otp";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public String getHelpText() {
        return "Validates a code sent via SMS to the user's mobile phone.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
            new ProviderConfigProperty("length", "Code length", "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, 6),
            new ProviderConfigProperty("ttl", "Time-to-live", "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE, "300"),
            new ProviderConfigProperty("senderId", "SenderId", "The sender ID is displayed as the message sender on the receiving device.", ProviderConfigProperty.STRING_TYPE, "Keycloak"),
            new ProviderConfigProperty("simulation", "Simulation mode", "In simulation mode, the SMS won't be sent, but printed to the server logs", ProviderConfigProperty.BOOLEAN_TYPE, true),
            new ProviderConfigProperty("countrycode", "Default country prefix", "Default country prefix that is assumed if user does not provide one.", ProviderConfigProperty.STRING_TYPE, "+49"),
            new ProviderConfigProperty("apiurl", "SMS API URL", "The path to the API that receives an HTTP request.", ProviderConfigProperty.STRING_TYPE, "https://example.com/api/sms/send"),
            new ProviderConfigProperty("apiuser", "Basic Auth Username (optional)", "If set, Basic Auth will be performed. Leave empty if not required.", ProviderConfigProperty.STRING_TYPE, ""),
            new ProviderConfigProperty("platformPartnerId", "Platform Partner ID", "Platform Partner ID for the SMS gateway", ProviderConfigProperty.STRING_TYPE, ""),
            new ProviderConfigProperty("normalizePhoneNumber", "Format phone number", "Normalize the phone number using the E164 standard.", ProviderConfigProperty.BOOLEAN_TYPE, false),
            new ProviderConfigProperty("forceRetryOnBadFormat", "Force retry on bad format", "If phone number formatting fails, force the user to retry.", ProviderConfigProperty.BOOLEAN_TYPE, false)
        );
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
