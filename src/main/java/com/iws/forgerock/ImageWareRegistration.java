/*
Ï * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */

package com.iws.forgerock;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.iws.forgerock.gmi.entity.Application;
import com.iws.forgerock.gmi.entity.Person;
import com.iwsinc.usermanager.client.OauthBearerToken;
import com.iwsinc.usermanager.exception.UserManagerCallFailedException;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.shared.debug.Debug;

import java.io.IOException;
import java.util.List;
import java.util.ResourceBundle;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextOutputCallback;

//<<<<<<< Updated upstream
//=======
//>>>>>>> Stashed changes

/**
 * A node that creates a User in ImageWare's GoVerifyID backend for mobile biometric enrollment and verification
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = ImageWareRegistration.Config.class)
public class ImageWareRegistration extends SingleOutcomeNode {

	private static final String BUNDLE = "com/iws/forgerock/ImageWareRegistration";

	private final CoreWrapper coreWrapper;
	private final static String DEBUG_FILE = "ImageWareRegistration";
	private Debug debug = Debug.getInstance(DEBUG_FILE);
	
	private String gmiServerURL;
	private OauthBearerToken bearerToken;

	private String getGmiServerURL() { return gmiServerURL; }

	private void setGmiServerURL(String gmiServerUrl) { this.gmiServerURL = gmiServerUrl; }
	
	private OauthBearerToken getBearerToken() { return bearerToken; }

	private void setBearerToken(OauthBearerToken bearerToken) { this.bearerToken = bearerToken; }

	/**
	 * Configuration for the node.
	 */
	public interface Config {
	}

	@Inject
	public ImageWareRegistration(CoreWrapper coreWrapper) {
		this.coreWrapper = coreWrapper;
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {

		JsonValue sharedState = context.sharedState;

		if (sharedState.isDefined(ImageWareCommon.IMAGEWARE_SHOULD_CHECK)) {
			sharedState.remove(ImageWareCommon.IMAGEWARE_SHOULD_CHECK);
			return goToNext().replaceSharedState(sharedState).build();
		}

		ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(ImageWareRegistration.BUNDLE,
				ImageWareRegistration.class.getClassLoader());
		String userRegistrationMessage = bundle.getString("registrationMessage");
		String userSelfRegisterInfoTemplate = bundle.getString("selfRegistrationMessage");
		String userTenantRegisterInfoTemplate = bundle.getString("tenantRegistrationMessage");

		ScriptTextOutputCallback buttonScript = new ScriptTextOutputCallback("document.getElementById" +
				"('loginButton_0').value='Registration Complete'");

//		check call back status and go to true when already showing the callback
//		check for both the script and text output callbacks
		List<? extends Callback> incomingCallbacks = context.getAllCallbacks();
		boolean foundScript = false;
		boolean foundText = false;

		for (Callback cb : incomingCallbacks) {
			if (cb instanceof ScriptTextOutputCallback && ((ScriptTextOutputCallback)cb).getMessage().equals
					(buttonScript.getMessage())) {
				foundScript = true;
			}

			if (cb instanceof TextOutputCallback && (((TextOutputCallback)cb).getMessage().contains(
					userRegistrationMessage))) {
				foundText = true;
			}
		}
		if (foundScript && foundText) return Action.send(incomingCallbacks).replaceSharedState(sharedState.copy()
				.put(ImageWareCommon.IMAGEWARE_SHOULD_CHECK, "true")).build();
		
		
		// NOTE: The user being registered is a Person entity in GMI
		// Need both username and email from user interface or LDAP record
		// Step 1: validate the user/email address
		String username = sharedState.get(USERNAME).asString();
		debug.message("Username {}.", username);

		ImageWareCommon.EmailObject emailObject = new ImageWareCommon.EmailObject(coreWrapper, bundle, sharedState,
				username).getEmailObject();
		if (emailObject.isException()) return Action.send(emailObject.getCallbacks()).build();
		String emailAddress = emailObject.getEmailAddress();
		sharedState = emailObject.getSharedState();
		debug.message("Email Address {}.", emailAddress);

		String tenant = context.sharedState.get(ImageWareCommon.IMAGEWARE_TENANT_NAME).asString();
		String applicationName = context.sharedState.get(ImageWareCommon.IMAGEWARE_PARAM_APPLICATION_NAME).asString();
		setGmiServerURL(context.sharedState.get(ImageWareCommon.IMAGEWARE_GMI_SERVER).asString());

		TokenService tokenService = TokenService.getInstance();

		// Step 2: authorize oauth client
		setBearerToken(tokenService.getBearerToken());
		
		// Step 3: add GMI person 
		try {
			addUserAsPersonToGmi(emailAddress, tenant);
		} catch (NodeProcessException ex) {
				return Action.send(ImmutableList.of(new TextOutputCallback(0, ex.getMessage()), new
						ScriptTextOutputCallback(ImageWareCommon.getReturnToLoginJS()))).build();
		} catch (ImageWareCommon.UnauthorizedException e) {
			tokenService.setBearerToken(null);
			setBearerToken(tokenService.getBearerToken());
			try {
				addUserAsPersonToGmi(emailAddress, tenant);
			} catch (IOException | ImageWareCommon.UnauthorizedException e1) {
				throw new NodeProcessException(e1);
			}
		} catch (IOException e) {
			throw new NodeProcessException(e);
		}
		// Step 4: user needs to download GoVerifyID app and register with email address
		//	upon success, user will get a registration email
		//	after completing the registration step, the user will receive an Enroll Message on their mobile device
			
		
		// If the GMI TenantApplication.validationType property is set to "email" then this user will be able to
		// self-register
		// Otherwise the user must wait for Tenant Admin to finalize the registration process        
		String userRegisterInfo = userRegistrationMessage + String.format(userSelfRegisterInfoTemplate,
				applicationName);

		if (!getTenantApplication(tenant, applicationName).getValidationType().equals(ImageWareCommon
				.IMAGEWARE_EMAIL_VALIDATION_TYPE)) {
			userRegisterInfo = userRegistrationMessage + userTenantRegisterInfoTemplate;
		}
		return Action.send(ImmutableList.of(new TextOutputCallback(0, userRegisterInfo), buttonScript))
				.replaceSharedState(sharedState.put(ImageWareCommon.IMAGEWARE_SHOULD_CHECK, "true")).build();
		
	}

	private Application getTenantApplication(String tenant, String applicationName) throws NodeProcessException {
		Application application = null;
		CloseableHttpResponse response = null;
		OauthBearerToken token = getBearerToken();

		try {
			HttpGet httpGet = new HttpGet(gmiServerURL + "/tenant/" + tenant + "/app/" + applicationName);
			httpGet.setHeader("Content-Type", "application/json");
			httpGet.setHeader("Authorization", "Bearer " + token.getAccessToken());

			CloseableHttpClient httpclient = HttpClients.createSystem();

			try {
				response = httpclient.execute(httpGet);
				if (response != null) {
					// get entity from response
					org.apache.http.HttpEntity entity = response.getEntity();

					String jsonResponse = EntityUtils.toString(entity);

					// investigate response for success/failure
					if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
						throw ImageWareCommon.getUnauthorizedException("Unauthorized access. May need a new OAuth token");
					}			
					else if (response.getStatusLine().getStatusCode() == org.apache.http.HttpStatus.SC_OK) {
						ObjectMapper objectMapper = new ObjectMapper();
						objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
						application = objectMapper.readValue(jsonResponse, Application.class);

						debug.message("json from GMI server: '{}'", jsonResponse);
					}
					else {
						UserManagerCallFailedException e = new UserManagerCallFailedException();
						String msg = String.format("Error in contacting GMI Server. Status: %s", response.getStatusLine());
						e.setMessageCode(msg);
						throw e;
					}

					// and ensure it is fully consumed
					EntityUtils.consume(entity);
				}
				else {
					debug.error("Error. No response from {}", ImageWareCommon.IMAGEWARE_APPLICATION_NAME);
				}

			}
			catch (Exception exp) {
				debug.error("Exception in {} getTenantApplication: '{}'", ImageWareCommon.IMAGEWARE_APPLICATION_NAME, exp.getMessage());
				throw exp;
			}
		}
		catch (Exception exp) {
			debug.error(exp.getMessage());

		}
		finally {
			if (response != null) try {
				response.close();
			} catch (Throwable ignored) {
			}
		}
		if (application == null) throw new NodeProcessException("GMI Application is null");

		return application;
	}

	
	private void addUserAsPersonToGmi(String emailAddress, String tenant) throws NodeProcessException,
			IOException, ImageWareCommon.UnauthorizedException {
		Person person = null;
		CloseableHttpResponse response;
		OauthBearerToken token = getBearerToken();
	
		String gmiUrl = getGmiServerURL() + "/tenant/" + tenant + "/person";
		HttpPost httpPost = new HttpPost(gmiUrl);
		httpPost.setHeader("Content-Type", "application/json");
		httpPost.setHeader("Authorization", "Bearer " + token.getAccessToken());
		String messageJson = "{" + "\"userId\" : \"" + emailAddress + "\" }";
		httpPost.setEntity(new StringEntity(messageJson));
		CloseableHttpClient httpclient = HttpClients.createSystem();
		response = httpclient.execute(httpPost);

		if (response != null) {
			// investigate response for success/failure
			int statusCode = response.getStatusLine().getStatusCode();
			if (statusCode == HttpStatus.SC_UNAUTHORIZED)
				throw ImageWareCommon.getUnauthorizedException(String.format("Unauthorized access. May need a new " +
						"OAuth token: %s", response.getStatusLine()));
			else if (statusCode == HttpStatus.SC_CONFLICT) {
				// if person exists in GMI, get the Person record
				String emailAddressEncoded = ImageWareCommon.encodeEmailAddress(emailAddress);

				HttpGet httpGet = new HttpGet(getGmiServerURL() + "/person?userId=" + emailAddressEncoded);
				httpGet.setHeader("Content-Type", "application/json");
				httpGet.setHeader("Authorization", "Bearer " + token.getAccessToken());


				CloseableHttpResponse getResponse = httpclient.execute(httpGet);

				if (getResponse != null) {
					// get entity from response
					HttpEntity entity = getResponse.getEntity();

					person = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).readValue
							(EntityUtils.toString(entity), Person.class);

					// and ensure it is fully consumed
					EntityUtils.consume(entity);
				}
			} else if (statusCode == HttpStatus.SC_CREATED) {
				// get entity from response
				HttpEntity entity = response.getEntity();

				person = new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).readValue
						(EntityUtils.toString(entity), Person.class);

				// and ensure it is fully consumed
				EntityUtils.consume(entity);

			} else {
				String msg = String.format("Cannot add user. Status: %s", response.getStatusLine());
				debug.error(msg);
			}
		}
		if (person == null) throw new NodeProcessException("GMI Person is null");
	}

}
