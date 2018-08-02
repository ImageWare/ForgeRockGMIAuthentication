package com.iws.forgerock;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
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
import org.forgerock.util.i18n.PreferredLocales;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.identity.shared.debug.Debug;

@Node.Metadata(outcomeProvider = ImageWareDecision.ImageWareDecisionOutcomeProvider.class, configClass =
		ImageWareDecision.Config.class)
public class ImageWareDecision implements Node {

	private static final String BUNDLE = "com/iws/forgerock/ImageWareDecision";

	private final static String DEBUG_FILE = "ImageWareDecision";
	private Debug debug = Debug.getInstance(DEBUG_FILE);

	/**
	 * Configuration for the node.
	 */
	interface Config {

	}

	/**
     * Create the node.
     */
    @Inject
    public ImageWareDecision() {
    }

    private ActionBuilder goTo(ImageWareDecisionOutcome outcome) { return Action.goTo(outcome.name()); }

	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		debug.message("ImageWareDecision started");
    	
    	Boolean verified = handleVerifyResponse(context.sharedState.get(Constants.IMAGEWARE_VERIFY_URL).asString(),
				context.sharedState.get(Constants.IMAGEWARE_OAUTH_BEARER_TOKEN).asString());
    	if (verified == null) {
        	return goTo(ImageWareDecisionOutcome.UNANSWERED).build();
    	}
    	else if (verified) {
        	return goTo(ImageWareDecisionOutcome.TRUE).build();
        }
        else {
        	return goTo(ImageWareDecisionOutcome.FALSE).build();
        }
	}


	private Boolean handleVerifyResponse(String verifyResponseUrl, String accessToken) throws NodeProcessException {
		Boolean verifyComplete = null;

		CloseableHttpResponse response;
		HttpGet httpGet = new HttpGet(verifyResponseUrl);
		httpGet.setHeader("Content-Type", "application/json");
		httpGet.setHeader("Authorization", "Bearer " + accessToken);

		debug.message("Processing verification...");

		try {
			response = HttpClients.createSystem().execute(httpGet);
		}
		catch (IOException e) {
			throw new NodeProcessException(e);
		}

		if (response == null) {
			String msg = String.format("Error in %s handleVerifyResponse: Verification Response from GMI " +
							"server was null", Constants.IMAGEWARE_APPLICATION_NAME);
			debug.error(msg);
			throw new NodeProcessException(msg);
		}
		// get entity from response
		HttpEntity entity = response.getEntity();


		// investigate response for success/failure
		if (response.getStatusLine().getStatusCode() != HttpStatus.SC_OK) {
			throw new NodeProcessException(String.format("Error in handleVerifyResponse contacting GMI " +
					"Server. Status: %s", response.getStatusLine()));
		}


		List<MessageResponse> messageResponses;
		try {
			messageResponses = Arrays.asList(new ObjectMapper().disable(DeserializationFeature.
					FAIL_ON_UNKNOWN_PROPERTIES).readValue(EntityUtils.toString(entity), MessageResponse[].class));
		} catch (IOException e) {
			throw new NodeProcessException(e);
		}

		// and ensure it is fully consumed
		try {
			EntityUtils.consume(entity);
		} catch (IOException e) {
			throw new NodeProcessException(e);
		}


		//Todo Not sure what is going on here. Why are there an array of message response? Also why does the decision
		//change based one result being true and others being false?
		for (MessageResponse messageResponse : messageResponses) {
			if (messageResponse.getTransactionType().equals("VERIFY") && messageResponse.getSucceeded()) {
				debug.message("Verification successful");
				verifyComplete = true;
			}
			else if (messageResponse.getTransactionType().equals("REJECT") && !messageResponse.getSucceeded() &&
					messageResponse.getRejectionInfo().equals("User rejected alert.")) {
				debug.message("Verification was rejected");
				verifyComplete = false;
			}
			else if (messageResponse.getTransactionType().equals("REJECT") && !messageResponse.getSucceeded()) {
				debug.message("Verification has failed or timed out");
				verifyComplete = false;
			}
		}

		return verifyComplete;
	}
	
	
    /**
     * The possible outcomes for the ImageWareDecision node.
     */
    public enum ImageWareDecisionOutcome {
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
    public static class ImageWareDecisionOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(ImageWareDecision.BUNDLE,
					ImageWareDecisionOutcomeProvider.class.getClassLoader());
            return ImmutableList.of(
                    new Outcome(ImageWareDecisionOutcome.TRUE.name(), bundle.getString("trueOutcome")),
                    new Outcome(ImageWareDecisionOutcome.FALSE.name(), bundle.getString("falseOutcome")),
                    new Outcome(ImageWareDecisionOutcome.UNANSWERED.name(), bundle.getString("unansweredOutcome")));
        }
    }
}