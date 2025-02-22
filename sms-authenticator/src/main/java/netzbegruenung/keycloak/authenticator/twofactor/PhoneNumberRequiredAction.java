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
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.ArrayList;
import java.util.Arrays;
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
		// TODO: get the alias from somewhere else or move config into realm or application scope
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		if (config == null) {
			logger.error("Failed to check 2FA enforcement, no config alias sms-2fa found");
			return;
		}
		boolean forceSecondFactorEnabled = Boolean.parseBoolean(config.getConfig().get("forceSecondFactor"));
		if (forceSecondFactorEnabled) {
			if (config.getConfig().get("whitelist") != null) {
				RoleModel whitelistRole = context.getRealm().getRole(config.getConfig().get("whitelist"));
				if (whitelistRole == null) {
					logger.errorf(
						"Failed configured whitelist role check [%s], make sure that the role exists",
						config.getConfig().get("whitelist")
					);
				} else if (context.getUser().hasRole(whitelistRole)) {
					// skip enforcement if user is whitelisted
					return;
				}
			}
			// add auth note for phone number input placeholder
			context.getAuthenticationSession().setAuthNote("mobileInputFieldPlaceholder",
				config.getConfig().getOrDefault("mobileInputFieldPlaceholder", ""));

			// Check if user has mobile number attribute
			if (context.getUser().getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE) != null) {
				// skip as mobile number is already set
				return;
			}

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

		// get the phone number formatting values from the config
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		boolean normalizeNumber = false;
		boolean forceRetryOnBadFormat = false;
		if (config != null && config.getConfig() != null) {
			normalizeNumber = Boolean.parseBoolean(config.getConfig().getOrDefault("normalizePhoneNumber", "false"));
			forceRetryOnBadFormat = Boolean.parseBoolean(config.getConfig().getOrDefault("forceRetryOnBadFormat", "false"));
		}

		// try to format the phone number
		if (normalizeNumber) {
			String formattedNumber = formatPhoneNumber(context, mobileNumber);
			if (formattedNumber != null && !formattedNumber.isBlank()) {
				mobileNumber = formattedNumber;
			} else if (forceRetryOnBadFormat) {
				logger.errorf("Failed phone number formatting checks for: %s", mobileNumber);
				String formatError = context.getAuthenticationSession().getAuthNote("formatError");
				if (formatError != null && !formatError.isBlank()) {
					handleInvalidNumber(context, formatError);
					return;
				}
			}
		}

		// Store mobile number as user attribute
		context.getUser().setSingleAttribute(MOBILE_NUMBER_ATTRIBUTE, mobileNumber);
		logger.infof("Stored mobile number [%s] for user: %s", mobileNumber, context.getUser().getUsername());

		authSession.setAuthNote("mobile_number", mobileNumber);
		logger.infof("Add required action for phone validation: [%s], user: %s", mobileNumber, context.getUser().getUsername());
		context.getAuthenticationSession().addRequiredAction(PhoneValidationRequiredAction.PROVIDER_ID);
		context.success();
	}

	private void handleInvalidNumber(RequiredActionContext context, String error) {
		Response challenge = context.form()
			.setError(error)
			.setAttribute("mobileInputFieldPlaceholder", context.getAuthenticationSession().getAuthNote("mobileInputFieldPlaceholder"))
			.createForm("mobile_number_form.ftl");
		context.challenge(challenge);
	}

	/**
	 * Formats the provided mobile phone number to E164 standard.
	 *
	 * @param context		the current RequiredActionContext
	 * @param mobileNumber	the mobile phone number to be formatted
	 * @return				the formatted mobile phone number, null if the phone number is invalid or mobileNumber if the config was not found
	 */
	private String formatPhoneNumber(RequiredActionContext context, String mobileNumber) {
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		if (config == null || config.getConfig() == null) {
			logger.error("Failed format phone number, no config alias sms-2fa found");
			return mobileNumber;
		}
		final PhoneNumberUtil phoneNumberUtil = PhoneNumberUtil.getInstance();
		int countryNumber;
		// try to get the country code from the country number in the config, fallback on default DE
		try {
			countryNumber = Integer.parseInt(whitespacePattern.matcher(config.getConfig()
				.getOrDefault("countrycode", "49").replace("+", ""))
				.replaceAll(""));
		} catch (NumberFormatException e) {
			logger.warn("Failed to parse countrycode to int, using default value (49)", e);
			countryNumber = 49;
		}
		String nameCodeToUse = phoneNumberUtil.getRegionCodeForCountryCode(countryNumber);
		PhoneNumber originalPhoneNumberParsed;
		try {
			originalPhoneNumberParsed = phoneNumberUtil.parse(mobileNumber, nameCodeToUse);
		} catch (NumberParseException e) {
			logger.warn("Failed to parse phone number: " + mobileNumber, e);
			context.getAuthenticationSession().setAuthNote("formatError", "smsAuthPhoneNumberInvalid");
			return null;
		}

		// check if the number is valid
		if (!phoneNumberUtil.isValidNumber(originalPhoneNumberParsed)) {
			logger.warn("Phone number is not valid: " + mobileNumber);
			context.getAuthenticationSession().setAuthNote("formatError", "smsAuthPhoneNumberInvalid");
			return null;
		}

		// check if the number is a mobile number
		if (!phoneNumberUtil.getNumberType(originalPhoneNumberParsed).equals(PhoneNumberUtil.PhoneNumberType.MOBILE)) {
			logger.warn("Phone number is not a mobile number: " + mobileNumber);
			context.getAuthenticationSession().setAuthNote("formatError", "smsAuthPhoneNumberNotMobile");
			return null;
		}

		// check if the number is in allowed countries
		String allowedCountries = config.getConfig().get("allowedCountries");
		if (allowedCountries != null && !allowedCountries.isBlank()) {
			List<String> allowedCountriesList = new ArrayList<>();
			numberFilterSplitter.split(allowedCountries).forEach(allowedCountriesList::add);
			if (!allowedCountriesList.contains(phoneNumberUtil.getRegionCodeForNumber(originalPhoneNumberParsed))) {
				logger.warn("Phone number is not in allowed countries: " + mobileNumber);
				context.getAuthenticationSession().setAuthNote("formatError", "smsAuthPhoneNumberNotAllowed");
				return null;
			}
		}

		return phoneNumberUtil.format(originalPhoneNumberParsed, PhoneNumberUtil.PhoneNumberFormat.E164);
	}

	@Override
	public void close() {
	}
}
