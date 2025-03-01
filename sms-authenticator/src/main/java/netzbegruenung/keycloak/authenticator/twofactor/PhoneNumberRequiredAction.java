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
		if (context.getUser().getFirstAttribute(MOBILE_NUMBER_ATTRIBUTE) == null) {
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
