
package netzbegruenung.keycloak.authenticator.twofactor;

import org.jboss.logging.Logger;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.Response;

public class PhoneNumberRequiredAction implements RequiredActionProvider {

	public static final String PROVIDER_ID = "mobile_number_config";
	private static final String MOBILE_NUMBER_ATTRIBUTE = "mobile_number";

	private static final Logger logger = Logger.getLogger(PhoneNumberRequiredAction.class);

	@Override
	public InitiatedActionSupport initiatedActionSupport() {
		return InitiatedActionSupport.SUPPORTED;
	}

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
		// Don't add required action if we're in an authentication flow
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		if (authSession.getAuthNote("LOGIN_ATTEMPT") != null || 
		    authSession.getAuthNote("SELECTED_AUTH_METHOD") != null) {
			logger.infof("Skipping required action during authentication flow for user %s", 
				context.getUser().getUsername());
			return;
		}
		
		if (context.getUser().getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE) == null) {
			logger.infof("Adding required action for user %s - missing mobile number", 
				context.getUser().getUsername());
			context.getUser().addRequiredAction(PROVIDER_ID);
		}
	}

	@Override
	public void processAction(RequiredActionContext context) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		UserModel user = context.getUser();
		String phoneNumber = context.getHttpRequest().getDecodedFormParameters().getFirst("mobile_number");

		if (phoneNumber != null && !phoneNumber.trim().isEmpty()) {
			// Store the mobile number
			user.setSingleAttribute(MOBILE_NUMBER_ATTRIBUTE, phoneNumber);
			context.success();
		} else {
			Response challenge = context.form()
				.setError("missingMobileNumber")
				.createForm("mobile_number_form.ftl");
			context.challenge(challenge);
		}
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		Response challenge = context.form().createForm("mobile_number_form.ftl");
		context.challenge(challenge);
	}

	@Override
	public void close() {
	}
}
