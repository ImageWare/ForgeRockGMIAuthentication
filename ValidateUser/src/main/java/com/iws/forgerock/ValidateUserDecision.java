package com.iws.forgerock;

import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.util.i18n.PreferredLocales;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;

@Node.Metadata(outcomeProvider = ValidateUserDecision.ValidateUserDecisionOutcomeProvider.class, configClass = ValidateUserDecision.Config.class)
public class ValidateUserDecision implements Node
{

	private static final String BUNDLE = "com/iws/forgerock/ValidateUserDecision";
    
	private final Config config;
	private final CoreWrapper coreWrapper;
	private final static String DEBUG_FILE = "ValidateUserDecision";
	protected Debug debug = Debug.getInstance(DEBUG_FILE);

	/**
	 * Configuration for the node.
	 */
	public interface Config
	{

	}

	/**
     * Create the node.
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public ValidateUserDecision(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException 
    {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    private ActionBuilder goTo(ValidateUserOutcome outcome) {
        return Action.goTo(outcome.name());
    }

	@Override
	public Action process(TreeContext context) throws NodeProcessException
	{
		debug.message("ValidateUserDecision started");

    	String verifyResponseUrl = context.sharedState.get(Constants.IMAGEWARE_VERIFY_URL).asString();
    	String accessToken = context.sharedState.get(Constants.IMAGEWARE_OAUTH_BEARER_TOKEN).asString();
    	
    	Boolean verified = handleVerifyResponse(verifyResponseUrl, accessToken);
    	if (verified == null)
    	{
        	return goTo(ValidateUserOutcome.UNANSWERED).build();
    	}
    	else if (verified != null && verified)
        {
        	return goTo(ValidateUserOutcome.TRUE).build();
        }
        else 
        {
        	return goTo(ValidateUserOutcome.FALSE).build();
        }
	}


	private Boolean handleVerifyResponse(String verifyResponseUrl, String accessToken)
	{
		Boolean verifyComplete = null;

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
					
					debug.message("[" + DEBUG_FILE + "]: " + "json from GMI: '{}'", jsonResponse);

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
						String msg = String.format("Error in handleVerifyResponse contacting GMI Server. Status: %s", response.getStatusLine());
						Exception e = new Exception(msg);
						throw e;
					}

					// and ensure it is fully consumed
					EntityUtils.consume(entity);
				}
				else
				{
					debug.error("[" + DEBUG_FILE + "]: " + "Error in {} handleVerifyResponse: Verification Response from GMI server was null", Constants.IMAGEWARE_APPLICATION_NAME);
				}
			}
			catch (Exception exp)
			{
				debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} handleVerifyResponse: '{}'", Constants.IMAGEWARE_APPLICATION_NAME, exp);
				throw exp;
			}
		}
		catch (Exception ex)
		{
			debug.error("[" + DEBUG_FILE + "]: " + "Exception in {} handleVerifyResponse: '{}'", Constants.IMAGEWARE_APPLICATION_NAME, ex);
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

		return verifyComplete;
	}
	
	
    /**
     * The possible outcomes for the ValidateUserDecision node.
     */
    public enum ValidateUserOutcome 
    {
        // Successful authentication.
        TRUE,
        // Authentication failed.
        FALSE,
        // The GMI/GVID message has not been received yet.
        UNANSWERED
    }

    
    /**
     * Defines the possible outcomes from this Ldap node.
     */
    public static class ValidateUserDecisionOutcomeProvider implements OutcomeProvider 
    {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) 
        {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(ValidateUserDecision.BUNDLE, ValidateUserDecisionOutcomeProvider.class.getClassLoader());
            return ImmutableList.of(
                    new Outcome(ValidateUserOutcome.TRUE.name(), bundle.getString("trueOutcome")),
                    new Outcome(ValidateUserOutcome.FALSE.name(), bundle.getString("falseOutcome")),
                    new Outcome(ValidateUserOutcome.UNANSWERED.name(), bundle.getString("unansweredOutcome")));
        }
    }
}
