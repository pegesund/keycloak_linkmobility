package netzbegruenung.keycloak.authenticator.twofactor;

public class LoginBean {
    public boolean isRegistration() {
        return false;
    }

    public boolean isResetPassword() {
        return false;
    }

    public boolean isRememberMe() {
        return false;
    }

    public boolean isUsernameEditDisabled() {
        return false;
    }

    public boolean isAttemptedUsername() {
        return false;
    }
}
