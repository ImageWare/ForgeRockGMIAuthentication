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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.assistedinject.Assisted;
import com.iws.forgerock.ImageWareCommon.UnauthorizedException;
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
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;

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
	private ImageWareService imageWareService;

	private String getGmiServerURL() { return gmiServerURL; }

	private void setGmiServerURL(String gmiServerUrl) { this.gmiServerURL = gmiServerUrl; }
	
	private OauthBearerToken getBearerToken() { return bearerToken; }

	private void setBearerToken(OauthBearerToken bearerToken) { this.bearerToken = bearerToken; }
	
	ImageWareService getImageWareService()
	{
		return imageWareService;
	}

	void setImageWareService(ImageWareService imageWareService)
	{
		this.imageWareService = imageWareService;
	}
	

	/**
	 * Configuration for the node.
	 */
	interface Config {
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

		imageWareService = new ImageWareService(tokenService.getBearerToken(), gmiServerURL, bundle);
		
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
			} catch (ImageWareCommon.UnauthorizedException e1) {
				throw new NodeProcessException(e1);
			}
		}
		
		// Step 4: user needs to download GoVerifyID app and register with email address
		//	upon success, user will get a registration email
		//	after completing the registration step, the user will receive an Enroll Message on their mobile device
			
		
		// If the GMI TenantApplication.validationType property is set to "email" then this user will be able to
		// self-register
		// Otherwise the user must wait for Tenant Admin to finalize the registration process        
		String userRegisterInfo = userRegistrationMessage + String.format(userSelfRegisterInfoTemplate,
				applicationName);
		
		try {
			if (!getTenantApplication(tenant, applicationName).getValidationType().equals(ImageWareCommon
					.IMAGEWARE_EMAIL_VALIDATION_TYPE)) {
				userRegisterInfo = userRegistrationMessage + userTenantRegisterInfoTemplate;
			}
		} catch (NodeProcessException ex) {
				return Action.send(ImmutableList.of(new TextOutputCallback(0, ex.getMessage()), new
						ScriptTextOutputCallback(ImageWareCommon.getReturnToLoginJS()))).build();
		} catch (ImageWareCommon.UnauthorizedException e) {
			tokenService.setBearerToken(null);
			setBearerToken(tokenService.getBearerToken());
			try {
				if (!getTenantApplication(tenant, applicationName).getValidationType().equals(ImageWareCommon
						.IMAGEWARE_EMAIL_VALIDATION_TYPE)) {
					userRegisterInfo = userRegistrationMessage + userTenantRegisterInfoTemplate;
				}
			} catch (ImageWareCommon.UnauthorizedException e1) {
				throw new NodeProcessException(e1);
			}
		} 
		
		return Action.send(ImmutableList.of(new TextOutputCallback(0, userRegisterInfo), buttonScript))
				.replaceSharedState(sharedState.put(ImageWareCommon.IMAGEWARE_SHOULD_CHECK, "true")).build();
		
	}

	Application getTenantApplication(String tenant, String applicationName) throws NodeProcessException, UnauthorizedException {
		
		Application application = imageWareService.getTenantApplication(tenant, applicationName);
		if (application == null) throw new NodeProcessException("GMI Application is null");

		return application;
	}

	
	void addUserAsPersonToGmi(String emailAddress, String tenant) throws NodeProcessException, UnauthorizedException {		
		
		Person person = imageWareService.addPerson(emailAddress, tenant);
		if (person == null) throw new NodeProcessException("GMI Person is null");
	}

}
