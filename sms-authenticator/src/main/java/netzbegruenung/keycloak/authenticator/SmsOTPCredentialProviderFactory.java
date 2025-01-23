package netzbegruenung.keycloak.authenticator;

import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.credential.OTPCredentialModel;

public class SmsOTPCredentialProviderFactory implements CredentialProviderFactory<SmsOTPCredentialProvider> {
    public static final String PROVIDER_ID = "sms-otp";

    @Override
    public SmsOTPCredentialProvider create(KeycloakSession session) {
        return new SmsOTPCredentialProvider(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
