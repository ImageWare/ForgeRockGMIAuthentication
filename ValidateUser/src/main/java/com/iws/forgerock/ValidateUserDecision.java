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

import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.assistedinject.Assisted;
import com.iwsinc.usermanager.exception.UserManagerCallFailedException;
import com.sun.identity.shared.debug.Debug;

/** 
 * A node that checks to see if zero-page login headers have specified username and shared key 
 * for this request. 
 */
@Node.Metadata(outcomeProvider  = AbstractDecisionNode.OutcomeProvider.class,
               configClass      = ValidateUserDecision.Config.class)
public class ValidateUserDecision extends AbstractDecisionNode {

    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "ValidateUserDecision";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);

    /**
     * Configuration for the node.
     */
    public interface Config {
       
    }


    /**
     * Create the node.
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public ValidateUserDecision(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

    	Boolean verified = false;
    	String verifyResponseUrl = context.sharedState.get(Constants.IMAGEWARE_VERIFY_URL).asString();
    	String accessToken = context.sharedState.get(Constants.IMAGEWARE_OAUTH_BEARER_TOKEN).asString();
    	debug.error("[" + DEBUG_FILE + "]: " + "access token {}, verify response url {}.", accessToken, verifyResponseUrl);
    	//int expiresInSeconds = 120;
    	
    	verified = handleVerifyResponse(verifyResponseUrl, accessToken);
    	if (verified == null)
    	{
    		//return goTo(ValidateUserOutcomeProvider.UNANSWERED).build();
        	return goTo(false).build();
    	}
    	else if (verified != null && verified)
        {
        	return goTo(true).build();
        }
        else 
        {
        	return goTo(false).build();
        }
    }
    

	private Boolean handleVerifyResponse(String verifyResponseUrl, String accessToken)
	{
		Boolean verifyComplete = null;
		boolean messageComplete = false;

//		int iterateCount = expiresInSeconds / 3;
//		for (int i = 0; i < iterateCount; i++)
//		{
//			try
//			{
//				Thread.sleep((long) (1000 * 2.5));
//			}
//			catch (InterruptedException e)
//			{
//				debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} Thread.sleep: '{}'", Constants.IMAGEWARE_APPLICATION_NAME, e);
//			}

			CloseableHttpResponse response = null;

			try
			{
				HttpGet httpGet = new HttpGet(verifyResponseUrl);
				httpGet.setHeader("Content-Type", "application/json");
				httpGet.setHeader("Authorization", "Bearer " + accessToken);

				CloseableHttpClient httpclient = HttpClients.createSystem();

				try
				{

					debug.message("[" + DEBUG_FILE + "]: " + "processing verification...");
					
					response = httpclient.execute(httpGet);
					if (response != null)
					{
						// get entity from response
						org.apache.http.HttpEntity entity = response.getEntity();
						String jsonResponse = EntityUtils.toString(entity);
						
						debug.message("[" + DEBUG_FILE + "]: " + "json from  GMI: '{}'", jsonResponse);

						// investigate response for success/failure
						if (response.getStatusLine().getStatusCode() == org.apache.http.HttpStatus.SC_OK)
						{
							ObjectMapper objectMapper = new ObjectMapper();
							// ignore existing Person Metadata and
							// BiometricMetadata properties which are not
							// included in com.iwsinc.forgerock.Person class
							objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
							List<MessageResponse> messageResponses = Arrays.asList(objectMapper.readValue(jsonResponse, MessageResponse[].class));

							for (MessageResponse messageResponse : messageResponses)
							{
								if (messageResponse.getTransactionType().equals("VERIFY") && messageResponse.getSucceeded())
								{
									debug.message("[" + DEBUG_FILE + "]: " + "Verification successful");
									verifyComplete = true;
								}
								else if (messageResponse.getTransactionType().equals("REJECT") && !messageResponse.getSucceeded() && messageResponse.getRejectionInfo().equals("User rejected alert."))
								{
									debug.message("[" + DEBUG_FILE + "]: " + "Verification was rejected");
									verifyComplete = false;

								}
								else if (messageResponse.getTransactionType().equals("REJECT") && !messageResponse.getSucceeded())
								{
									debug.message("[" + DEBUG_FILE + "]: " + "Verification has failed or timed out");
									verifyComplete = false;

								}
							}
						}
						else
						{
							UserManagerCallFailedException e = new UserManagerCallFailedException();
							String msg = String.format("Error in contacting UserManager. Status: %s", response.getStatusLine());
							e.setMessageCode(msg);
							throw e;
						}

						// and ensure it is fully consumed
						EntityUtils.consume(entity);
					}
					else
					{

					}

				}
				catch (Exception exp)
				{
					debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} validateUser: '{}'", Constants.IMAGEWARE_APPLICATION_NAME, exp);
					throw exp;
				}

			}
			catch (Exception ex)
			{
				debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} validateUser: '{}'", Constants.IMAGEWARE_APPLICATION_NAME, ex);

			}
			finally
			{
				if (response != null)
				{
					try
					{
						response.close();
					}
					catch (Throwable t)
					{
					}
				}
			}

			if (verifyComplete != null)
			{
				messageComplete = true;
//				break;
			}
//		}

//		if (!messageComplete)
//		{
//			debug.message("[" + DEBUG_FILE + "]: " + "Verification has timed out");
//		}

		return verifyComplete;
	}

}