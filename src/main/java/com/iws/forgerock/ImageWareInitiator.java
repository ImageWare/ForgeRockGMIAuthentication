/*
 * The contents of this file are subject to the terms of the Common Development and
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

import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.sm.annotations.adapters.Password;

import com.google.inject.assistedinject.Assisted;
import com.iws.forgerock.ImageWareCommon.UnauthorizedException;
import com.iws.forgerock.gmi.entity.DeviceApplication;
import com.iws.forgerock.gmi.entity.Message;
import com.iws.forgerock.gmi.entity.Person;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * A node that verifies a user account exists in the ImageWare GoVerifyID user
 * repository and sends a biometric verification message for ForgeRock authentication
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = ImageWareInitiator.Config.class)
public class ImageWareInitiator extends AbstractDecisionNode {
	
	
	private final Config config;
	private final CoreWrapper coreWrapper;
	private final static String DEBUG_FILE = "ImageWareInitiator";
	private Debug debug = Debug.getInstance(DEBUG_FILE);
	private Person person;
	private ImageWareService imageWareService;
	private ResourceBundle resourceBundle;
	
	Person getPerson()
	{
		return person;
	}

	void setPerson(Person person)
	{
		this.person = person;
	}

	ImageWareService getImageWareService()
	{
		return imageWareService;
	}

	void setImageWareService(ImageWareService imageWareService)
	{
		this.imageWareService = imageWareService;
	}

	void setResourceBundle(ResourceBundle resourceBundle) { this.resourceBundle = resourceBundle; }
	
	private ResourceBundle getResourceBundle() { return resourceBundle; }

	/**
	 * Configuration for the node.
	 */
	public interface Config {
		@Attribute(order = 100,  validators = {RequiredValueValidator.class})
		default String tenantName() { return ""; }

		@Attribute(order = 200,  validators = {RequiredValueValidator.class})
		default String clientName() { return ""; }

		@Attribute(order = 300, validators = {RequiredValueValidator.class})
		@Password
		char[] clientSecret();

		@Attribute(order = 400,  validators = {RequiredValueValidator.class})
		default String userManagerURL() { return "https://gmi-ha.iwsinc.com/usermanager"; }

		@Attribute(order = 500,  validators = {RequiredValueValidator.class})
		default String gmiServerURL() { return "https://gmi-ha.iwsinc.com/gmiserver"; }

		@Attribute(order = 600,  validators = {RequiredValueValidator.class})
		default String gmiApplicationName() { return "GoVerifyID"; }

		@Attribute(order = 700,  validators = {RequiredValueValidator.class})
		default String gmiTemplateName() { return "GVID_VERIFY_CHOICE"; }

		@Attribute(order = 800,  validators = {RequiredValueValidator.class})
		default String messageReason() { return "ForgeRock custom authentication test message"; }
		
		@Attribute(order = 900,  validators = {RequiredValueValidator.class})
		default int messageExpiresInSeconds() { return 180; }
	}

	/**
	 * Create the node.
	 * 
	 * @param config
	 *            The service config.
	 */
	@Inject
	public ImageWareInitiator(@Assisted Config config, CoreWrapper coreWrapper) {
		this.config = config;
		this.coreWrapper = coreWrapper;
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {

		debug.message("ImageWareInitiator started");
		
		setResourceBundle(context.request.locales.getBundleInPreferredLocale(ImageWareCommon.IMAGEWARE_INITIATOR_BUNDLE,
				ImageWareInitiator.class.getClassLoader()));

		JsonValue sharedState = context.sharedState;
		String username = sharedState.get(USERNAME).asString();
		debug.message("Username {}.", username);


		ImageWareCommon.EmailObject emailObject = new ImageWareCommon.EmailObject(coreWrapper, getResourceBundle(),
				sharedState, username).getEmailObject();
		if (emailObject.isException()) return Action.send(emailObject.getCallbacks()).build();
		String emailAddress = emailObject.getEmailAddress();
		sharedState = emailObject.getSharedState();
		debug.message("Email Address {}.", emailAddress);


		TokenService.setConfig(config);
		TokenService tokenService = TokenService.getInstance();
		
		String tenant = config.tenantName();
		String gmiServerURL = config.gmiServerURL();
		

		imageWareService = new ImageWareService(tokenService.getBearerToken(), gmiServerURL, getResourceBundle());

		try {
			person = validateUser(emailAddress);
		} catch (UnauthorizedException ue) {
			tokenService.setBearerToken(null);
			
			try {
				person = validateUser(emailAddress);
			} catch (UnauthorizedException e) {
				debug.error("Cannot successfully use new UserManager OAuth token.");
				throw new NodeProcessException(e);
			}
		}
		if (person == null) {
			return goTo(false).replaceSharedState(sharedState.
					put(ImageWareCommon.IMAGEWARE_OAUTH_BEARER_TOKEN, tokenService.getBearerToken().getAccessToken()).
					put(ImageWareCommon.IMAGEWARE_GMI_SERVER, gmiServerURL).
					put(ImageWareCommon.IMAGEWARE_TENANT_NAME, tenant).
					put(ImageWareCommon.IMAGEWARE_PARAM_APPLICATION_NAME, config.gmiApplicationName())).build();
		}
		
		debug.message("validateUser returning and moving to next step");

		String templatePath = gmiServerURL + "/tenant/" + tenant + "/app/" + config.gmiApplicationName() + "/template/"
				+ config.gmiTemplateName();
		String messageJson = "{" + "\"maxResponseAttempts\" : 3," + "\"template\" : \"" + templatePath + "\"," +
				"\"metadata\" :" + "{" + "\"reason\" :\"" + config.messageReason() + "\"" + "}," + "\"expiresIn\" :"
				+ config.messageExpiresInSeconds() + "}";
		debug.message("IWS Message JSON: {} ", messageJson);

		try {
			biometricVerifyUser(sharedState, messageJson);
		} catch (UnauthorizedException ue) {
			tokenService.setBearerToken(null);
			try {
				biometricVerifyUser(sharedState, messageJson);
			} catch (UnauthorizedException e) {
				debug.error("Cannot successfully use new UserManager OAuth token.");
				throw new NodeProcessException(e);
			}
			
		}
		debug.message("biometricVerifyUser returning and completing authentication");
		
		return goTo(true).replaceSharedState(sharedState.
				put(ImageWareCommon.IMAGEWARE_OAUTH_BEARER_TOKEN, tokenService.getBearerToken().getAccessToken()))
				.build();
	}
	

	void biometricVerifyUser(JsonValue sharedState, String messageJson) throws NodeProcessException, UnauthorizedException {

		Message message = imageWareService.postGMIMessage(config.tenantName(), config.gmiApplicationName(), config.gmiTemplateName(), person, messageJson);


		if (message == null || message.getMessageId() == null) throw new NodeProcessException(getResourceBundle()
				.getString("cannotReadGmiMessage"));

		String gmiVerifyUrlTemp = config.gmiServerURL() + "/tenant/" + config.tenantName() + "/person/" + person.getId() + "/message/%s/response";
		
		// share verification response url in state for retrieval later
		sharedState.put(ImageWareCommon.IMAGEWARE_VERIFY_URL, String.format(gmiVerifyUrlTemp, message.getMessageId()));
		debug.message("biometricVerifyUser returning true for sending message and moving to next step");
	}
	
	
	Person validateUser(String emailAddress) throws
			UnauthorizedException, NodeProcessException {
		
		person = imageWareService.getGMIPerson(emailAddress);

		if (person == null) throw new NodeProcessException("Person is null");
		
		// validate person is registered
		List<DeviceApplication> devices = imageWareService.getPersonDevices(person, config.gmiApplicationName());

		// check for not yet registered or not yet enrolled scenario
		if ( devices.isEmpty() || person.getData() == null || person.getData().getBiometricMetadata() == null ) {
			// not registered or not enrolled
			return null;
		} else return person;
	}
}