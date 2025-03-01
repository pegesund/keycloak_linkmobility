/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator.twofactor;

import com.google.common.base.Splitter;
import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.requiredactions.WebAuthnRegisterFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class PhoneNumberRequiredAction implements RequiredActionProvider {

	public static final String PROVIDER_ID = "mobile_number_config";
	private static final String MOBILE_NUMBER_ATTRIBUTE = "mobile_number";

	private static final Logger logger = Logger.getLogger(PhoneNumberRequiredAction.class);
	private static final Splitter numberFilterSplitter = Splitter.on("##");
	private static final Pattern nonDigitPattern = Pattern.compile("[^0-9+]");
	private static final Pattern whitespacePattern = Pattern.compile("\\s+");

	@Override
	public InitiatedActionSupport initiatedActionSupport() {
		return InitiatedActionSupport.SUPPORTED;
	}

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
		// Check if the user already has a mobile number
		String mobileNumber = context.getUser().getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE);
		if (mobileNumber != null && !mobileNumber.trim().isEmpty()) {
			return;
		}

		// Check if the required action is already set
		Set<String> availableRequiredActions = Set.of(
			PhoneNumberRequiredAction.PROVIDER_ID,
			PhoneValidationRequiredAction.PROVIDER_ID,
			UserModel.RequiredAction.CONFIGURE_TOTP.name(),
			WebAuthnRegisterFactory.PROVIDER_ID,
			UserModel.RequiredAction.UPDATE_PASSWORD.name()
		);
		Set<String> authSessionRequiredActions = context.getAuthenticationSession().getRequiredActions();
		authSessionRequiredActions.retainAll(availableRequiredActions);
		if (!authSessionRequiredActions.isEmpty()) {
			// skip as relevant required action is already set
			return;
		}

		Stream<String> usersRequiredActions = context.getUser().getRequiredActionsStream();
		if (usersRequiredActions.noneMatch(availableRequiredActions::contains)) {
			logger.infof(
				"No mobile number configured for user: %s, setting required action for SMS authenticator",
				context.getUser().getUsername()
			);
			context.getUser().addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		}
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		Response challenge = context.form()
			.setAttribute("mobileInputFieldPlaceholder", context.getAuthenticationSession().getAuthNote("mobileInputFieldPlaceholder"))
			.createForm("mobile_number_form.ftl");
		context.challenge(challenge);
	}

	@Override
	public void processAction(RequiredActionContext context) {
		String mobileNumber = nonDigitPattern.matcher(context.getHttpRequest().getDecodedFormParameters().getFirst("mobile_number")).replaceAll("");
		AuthenticationSessionModel authSession = context.getAuthenticationSession();

		try {
			// Format the phone number if needed
			String formattedNumber = formatPhoneNumber(context, mobileNumber);
			if (formattedNumber != null && !formattedNumber.isBlank()) {
				mobileNumber = formattedNumber;
			}

			// Store mobile number temporarily in auth session
			authSession.setAuthNote("mobile_number", mobileNumber);
			logger.infof("Adding required action for phone validation: [%s], user: %s", mobileNumber, context.getUser().getUsername());
			
			// Add validation required action and remove this one
			context.getUser().addRequiredAction(PhoneValidationRequiredAction.PROVIDER_ID);
			context.getUser().removeRequiredAction(PROVIDER_ID);
			context.success();
		} catch (Exception e) {
			logger.error("Failed to process mobile number", e);
			handleInvalidNumber(context, "smsAuthInvalidNumber");
		}
	}

	private void handleInvalidNumber(RequiredActionContext context, String error) {
		Response challenge = context.form()
			.setError(error)
			.createForm("mobile_number_form.ftl");
		context.challenge(challenge);
	}

	/**
	 * Formats the provided mobile phone number to E164 standard.
	 *
	 * @param context		the current RequiredActionContext
	 * @param mobileNumber	the mobile phone number to be formatted
	 * @return				the formatted mobile phone number, null if the phone number is invalid
	 */
	private String formatPhoneNumber(RequiredActionContext context, String mobileNumber) {
		final PhoneNumberUtil phoneNumberUtil = PhoneNumberUtil.getInstance();
		String countryCode = "+49"; // Default to Germany

		try {
			PhoneNumber parsedNumber = phoneNumberUtil.parse(mobileNumber, "DE");
			if (!phoneNumberUtil.isValidNumber(parsedNumber)) {
				logger.warn("Invalid phone number format: " + mobileNumber);
				return null;
			}
			return phoneNumberUtil.format(parsedNumber, PhoneNumberUtil.PhoneNumberFormat.E164);
		} catch (NumberParseException e) {
			logger.warn("Failed to parse phone number: " + mobileNumber, e);
			return null;
		}
	}

	@Override
	public void close() {
	}
}
