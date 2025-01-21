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
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator.gateway;

import java.util.Map;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.jboss.logging.Logger;
import java.util.regex.Pattern;

public class ApiSmsService implements SmsService{

	private static final Logger logger = Logger.getLogger(SmsServiceFactory.class);
	private static final Pattern plusPrefixPattern = Pattern.compile("\\+");

	private final String apiurl;
	private final String apiuser;
	private final String source;
	private final String countrycode;
	private final String platformPartnerId;
	
	ApiSmsService(Map<String, String> config) {
		apiurl = config.get("apiurl");
		apiuser = config.getOrDefault("apiuser", "");
		source = config.getOrDefault("source", "LINK TEST");
		countrycode = config.getOrDefault("countrycode", "");
		platformPartnerId = config.getOrDefault("platformPartnerId", "");
	}

	public void send(String phoneNumber, String message) {
		phoneNumber = clean_phone_number(phoneNumber, countrycode);
		HttpRequest request = null;
		var client = HttpClient.newHttpClient();
		try {
			var request_builder = HttpRequest.newBuilder()
				.uri(URI.create(apiurl))
				.header("Content-Type", "application/json")
				.POST(HttpRequest.BodyPublishers.ofString(createJsonBody(phoneNumber, message)));

			if (apiuser != null && !apiuser.isEmpty()) {
				request = request_builder.setHeader("Authorization", apiuser).build();
			} else {
				request = request_builder.build();
			}

			// Log the curl equivalent
			String jsonBody = createJsonBody(phoneNumber, message);
			logger.infof("Equivalent curl command: curl -X POST '%s' -H 'Content-Type: application/json' %s -d '%s'",
				apiurl,
				apiuser != null && !apiuser.isEmpty() ? "-H 'Authorization: Basic " + apiuser + "'" : "",
				jsonBody);

			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

			int statusCode = response.statusCode();
			String payload = "Response: " + response.body();

			if (statusCode >= 200 && statusCode < 300) {
				logger.infof("Sent SMS to %s [%s]", phoneNumber, payload);
			} else {
				logger.errorf("Failed to send message to %s [%s]. Validate your config.", phoneNumber, payload);
			}
		} catch (Exception e) {
			logger.errorf(e, "Failed to send message to %s with request: %s. Validate your config.", phoneNumber, request != null ? request.toString() : "null");
		}
	}

	private String createJsonBody(String phoneNumber, String message) {
		return String.format(
			"{\"source\":\"%s\",\"destination\":\"%s\",\"userData\":\"%s\",\"platformId\":\"SMS\",\"platformPartnerId\":\"%s\"}",
			source,
			phoneNumber,
			message,
			platformPartnerId
		);
	}

	private static String clean_phone_number(String phone_number, String countrycode) {
		/*
		 * This function tries to correct several common user errors. If there is no default country
		 * prefix, this function does not dare to touch the phone number.
		 * https://en.wikipedia.org/wiki/List_of_mobile_telephone_prefixes_by_country
		 */
		if (countrycode == null || countrycode.isEmpty()) {
			logger.infof("Clean phone number: no country code set, return %s", phone_number);
			return phone_number;
		}
		String country_number = plusPrefixPattern.matcher(countrycode).replaceFirst("");
		// convert 47 to +47
		if (phone_number.startsWith(country_number)) {
			phone_number = phone_number.replaceFirst(country_number, countrycode);
			logger.infof("Clean phone number: convert 47 to +47, set phone number to %s", phone_number);
		}
		// convert 0047 to +47
		if (phone_number.startsWith("00" + country_number)) {
			phone_number = phone_number.replaceFirst("00" + country_number, countrycode);
			logger.infof("Clean phone number: convert 0047 to +47, set phone number to %s", phone_number);
		}
		// convert +470176 to +47176
		if (phone_number.startsWith(countrycode + '0')) {
			phone_number = phone_number.replaceFirst("\\+" + country_number + '0', countrycode);
			logger.infof("Clean phone number: convert +470176 to +47176, set phone number to %s", phone_number);
		}
		// convert 0 to +47
		if (phone_number.startsWith("0")) {
			phone_number = phone_number.replaceFirst("0", countrycode);
			logger.infof("Clean phone number: convert 0 to +47, set phone number to %s", phone_number);
		}
		return phone_number;
	}
}
