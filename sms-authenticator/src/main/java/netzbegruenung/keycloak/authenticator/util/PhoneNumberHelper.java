package netzbegruenung.keycloak.authenticator.util;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.UserModel;
import jakarta.ws.rs.core.Response;

/**
 * Helper class for phone number related operations.
 * Centralizes common functionality used across authenticators.
 */
public class PhoneNumberHelper {
    private static final Logger logger = Logger.getLogger(PhoneNumberHelper.class);

    public static final String MOBILE_NUMBER_ATTRIBUTE = "mobile_number";
    public static final String MOBILE_NUMBER_FIELD = "mobile_number";
    public static final String MOBILE_NUMBER_FORM = "mobile_number_form.ftl";

    private PhoneNumberHelper() {
        // Utility class, no instantiation
    }

    /**
     * Gets the mobile number for a user.
     *
     * @param user The user to get the mobile number for
     * @return The mobile number or null if not set
     */
    public static String getMobileNumber(UserModel user) {
        return user.getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE);
    }

    /**
     * Sets the mobile number for a user.
     *
     * @param user The user to set the mobile number for
     * @param mobileNumber The mobile number to set
     */
    public static void setMobileNumber(UserModel user, String mobileNumber) {
        user.setSingleAttribute(MOBILE_NUMBER_ATTRIBUTE, mobileNumber);
        logger.infof("Set mobile number for user %s", user.getUsername());
    }

    /**
     * Checks if a user has a mobile number configured.
     *
     * @param user The user to check
     * @return true if the user has a mobile number, false otherwise
     */
    public static boolean hasMobileNumber(UserModel user) {
        String mobileNumber = getMobileNumber(user);
        return mobileNumber != null && !mobileNumber.trim().isEmpty();
    }

    /**
     * Creates a mobile number form challenge.
     *
     * @param context The authentication flow context
     * @param error Optional error message to display
     * @return Response containing the mobile number form
     */
    public static Response createMobileNumberFormChallenge(AuthenticationFlowContext context, String error) {
        if (error != null) {
            return context.form()
                .setError(error)
                .createForm(MOBILE_NUMBER_FORM);
        }
        return context.form()
            .createForm(MOBILE_NUMBER_FORM);
    }
}
