package com.iws.forgerock;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.iws.forgerock.ImageWareCommon.UnauthorizedException;
import com.iws.forgerock.gmi.entity.MessageResponse;
import com.iwsinc.usermanager.client.OauthBearerToken;
import com.sun.identity.shared.debug.Debug;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.ResourceBundle;
import javax.inject.Inject;

/**
 * A node that processes the result of an ImageWare biometric verification message for ForgeRock authentication
 */
@Node.Metadata(outcomeProvider = ImageWareDecision.ImageWareDecisionOutcomeProvider.class, configClass =
		ImageWareDecision.Config.class)
public class ImageWareDecision implements Node {

	static final String USER_REJECTED_ALERT_MESSAGE = "User rejected alert.";
	
	private static final String BUNDLE = "com/iws/forgerock/ImageWareDecision";

	private final static String DEBUG_FILE = "ImageWareDecision";
	private Debug debug = Debug.getInstance(DEBUG_FILE);
	private String gmiServerURL;
	private ResourceBundle resourceBundle;
	private ImageWareService imageWareService;
	

	private String getGmiServerURL() { return gmiServerURL; }

	private void setGmiServerURL(String gmiServerUrl) { this.gmiServerURL = gmiServerUrl; }
	
	private void setResourceBundle(ResourceBundle resourceBundle) { this.resourceBundle = resourceBundle; }
	
	private ResourceBundle getResourceBundle() { return resourceBundle; }


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
	public interface Config {

	}

	/**
     * Create the node.
     */
    @Inject
    public ImageWareDecision() {
    }

	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		
		debug.message("ImageWareDecision started");

		setResourceBundle(context.request.locales.getBundleInPreferredLocale(ImageWareDecision.BUNDLE,
				ImageWareDecisionOutcomeProvider.class.getClassLoader()));
        
		Boolean verified;
		
		TokenService tokenService = TokenService.getInstance();
		setGmiServerURL(context.sharedState.get(ImageWareCommon.IMAGEWARE_GMI_SERVER).asString());

		imageWareService = new ImageWareService(tokenService.getBearerToken(), gmiServerURL, getResourceBundle());
		
		try {
	    	verified = handleVerifyResponse(context.sharedState.get(ImageWareCommon.IMAGEWARE_VERIFY_URL).asString());
		}
		catch (UnauthorizedException ue) {
			tokenService.setBearerToken(null);
			
			try {
				verified = handleVerifyResponse(context.sharedState.get(ImageWareCommon.IMAGEWARE_VERIFY_URL).asString());
			}
			catch (UnauthorizedException e) {
				debug.error("Cannot successfully use new UserManager OAuth token.");
				throw new NodeProcessException(e);
			}
			
		}
		
		if (verified == null) {
        	return Action.goTo(ImageWareDecisionOutcome.UNANSWERED.name()).build();
    	}
    	else if (verified) {
        	return Action.goTo(ImageWareDecisionOutcome.TRUE.name()).build();
        }
        else {
        	return Action.goTo(ImageWareDecisionOutcome.FALSE.name()).build();
        }
	}


	Boolean handleVerifyResponse(String verifyResponseUrl) throws NodeProcessException, UnauthorizedException {

		debug.message("Processing verification...");
		debug.message("verifyResponseUrl {}.", verifyResponseUrl);
		Boolean verifyComplete = null;

		List<MessageResponse> messageResponses = imageWareService.getGMIMessageResponses(verifyResponseUrl);
		
		// Multiple responses are possible:
		// If the number of retries allowed is greater than 1 and if the user fails to verify the first time(s)
		// we must cycle through all the responses and find either a REJECT or a Successful VERIFY

		int msgCount = messageResponses.size();
		String m_count = Integer.toString(msgCount);
		debug.message("Message count {}.", m_count);
		if (msgCount > 0) {
			MessageResponse checkResponse;
			for (int i=0; i<msgCount; i++) {
				checkResponse = messageResponses.get(i);
				if(checkResponse.getTransactionType().equals("REJECT") && checkResponse.getRejectionInfo().equals(USER_REJECTED_ALERT_MESSAGE)) {
					debug.message("Verification was rejected");
					verifyComplete = false;
				}
				else if(checkResponse.getTransactionType().equals("REJECT")) {
					debug.message("Verification failed");
					verifyComplete = false;
				}
				else if (checkResponse.getTransactionType().equals("VERIFY") && checkResponse.getSucceeded()) {
					debug.message("Verification successful");
					verifyComplete = true;
				}
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
    				ImageWareDecision.class.getClassLoader());
            return ImmutableList.of(
                    new Outcome(ImageWareDecisionOutcome.TRUE.name(), bundle.getString("trueOutcome")),
                    new Outcome(ImageWareDecisionOutcome.FALSE.name(), bundle.getString("falseOutcome")),
                    new Outcome(ImageWareDecisionOutcome.UNANSWERED.name(), bundle.getString("unansweredOutcome")));
        }
    }
}
