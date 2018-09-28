package com.iws.forgerock;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.junit.Test;

import com.iws.forgerock.ImageWareCommon.UnauthorizedException;
import com.iws.forgerock.gmi.entity.MessageResponse;

public class ImageWareDecisionTest
{


	@Test
	public void testVerificationSuccess() throws NodeProcessException, UnauthorizedException
	{
		ImageWareDecision decision = new ImageWareDecision();
		ImageWareService imageWareService = mock(ImageWareService.class);
		
		String verifyResponseUrl = "";
		
		MessageResponse successResponse = new MessageResponse();
		successResponse.setTransactionType("VERIFY");
		successResponse.setSucceeded(true);
		
		List<MessageResponse> responses = new ArrayList<MessageResponse>();
		responses.add(successResponse);
		
		when(imageWareService.getGMIMessageResponses(verifyResponseUrl)).thenReturn(responses);
		
		decision.setImageWareService(imageWareService);
		Boolean result = decision.handleVerifyResponse(verifyResponseUrl);
		
		assertTrue("result should be true", result);
		
	}

	@Test
	public void testVerificationFailure() throws NodeProcessException, UnauthorizedException
	{
		ImageWareDecision decision = new ImageWareDecision();
		ImageWareService imageWareService = mock(ImageWareService.class);
		
		String verifyResponseUrl = "";
		
		MessageResponse failureResponse = new MessageResponse();
		failureResponse.setTransactionType("REJECT");
		failureResponse.setRejectionInfo("");
		
		List<MessageResponse> responses = new ArrayList<MessageResponse>();
		responses.add(failureResponse);
		
		when(imageWareService.getGMIMessageResponses(verifyResponseUrl)).thenReturn(responses);
		
		decision.setImageWareService(imageWareService);
		Boolean result = decision.handleVerifyResponse(verifyResponseUrl);
		
		assertFalse("result should not be true", result);
		
	}
	
	@Test
	public void testVerificationRejection() throws NodeProcessException, UnauthorizedException
	{
		ImageWareDecision decision = new ImageWareDecision();
		ImageWareService imageWareService = mock(ImageWareService.class);
		
		String verifyResponseUrl = "";
		
		MessageResponse rejectResponse = new MessageResponse();
		rejectResponse.setTransactionType("REJECT");
		rejectResponse.setRejectionInfo(ImageWareDecision.USER_REJECTED_ALERT_MESSAGE);
		
		List<MessageResponse> responses = new ArrayList<MessageResponse>();
		responses.add(rejectResponse);
		
		when(imageWareService.getGMIMessageResponses(verifyResponseUrl)).thenReturn(responses);
		
		decision.setImageWareService(imageWareService);
		Boolean result = decision.handleVerifyResponse(verifyResponseUrl);
		
		assertFalse("result should not be true", result);
		
	}
}
