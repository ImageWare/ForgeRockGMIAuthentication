package com.iws.forgerock;

import java.text.SimpleDateFormat;
import java.util.Date;

import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 *
 */
@XmlRootElement
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MessageResponse
{
	

	public MessageResponse()
	{
		
	}
	
	public MessageResponse(String tenant_code, String person_uuid, String message_uuid)
	{
		setTenantCode(tenant_code);
		setPersonUuid(person_uuid);
		setMessageUuid(message_uuid);
	}
	
	public MessageResponse(String tenant_code, String person_uuid)
	{
		setTenantCode(tenant_code);
		setPersonUuid(person_uuid);
	}
		
	public String getPersonUuid()
	{
		return m_person_uuid;
	}
	public void setPersonUuid(String person_uuid)
	{
		m_person_uuid = person_uuid;
	}
	public String getMessageUuid()
	{
		return m_message_uuid;
	}
	public void setMessageUuid(String message_uuid)
	{
		m_message_uuid = message_uuid;
	}
	public String getTenantCode()
	{
		return m_tenant_code;
	}
	public void setTenantCode(String tenant_code)
	{
		m_tenant_code = tenant_code;
	}
	public String getTransactionType()
	{
		return m_transaction_type;
	}
	public long getTransactionId()
	{
		return m_transaction_id;
	}
	public void setTransactionId(long transaction_id)
	{
		m_transaction_id = transaction_id;
	}
	public void setTransactionType(String transaction_type)
	{
		m_transaction_type = transaction_type;
	}
	public boolean getSucceeded()
	{
		return m_succeeded;
	}
	public void setSucceeded(boolean success)
	{
		m_succeeded = success;
	}
	public String getPostBackUrl()
	{
		return m_post_back_url;
	}
	public void setPostBackUrl(String post_back_url)
	{
		m_post_back_url = post_back_url;
	}
	public String getPostBackRequest()
	{
		return m_post_back_request;
	}
	public void setPostBackRequest(String post_back_request)
	{
		m_post_back_request = post_back_request;
	}
	public String getPostBackResponse()
	{
		return m_post_back_response;
	}
	public void setPostBackResponse(String post_back_response)
	{
		m_post_back_response = post_back_response;
	}
	public String getException()
	{
		return m_exception;
	}
	public void setException(String exception)
	{
		m_exception = exception;
	}
	public String getBeResponse()
	{
		return m_be_response;
	}
	public void setBeResponse(String be_response)
	{
		m_be_response = be_response;
	}
	public Integer getImageCount()
	{
		return m_image_count;
	}
	public void setImageCount(Integer image_count)
	{
		m_image_count = image_count;
	}
	public String getRejectionInfo()
	{
		return m_rejection_info;
	}
	public void setRejectionInfo(String rejection_info)
	{
		m_rejection_info = rejection_info;
	}
	public String getTemplateUri()
	{
		return m_template_uri;
	}
	public void setTemplateUri(String template_uri)
	{
		m_template_uri = template_uri;
	}
	public Date getCreatedDate()
	{
		return m_created_date;
	}
	public void setCreatedDate(Date created_date)
	{
		m_created_date = created_date;
	}
	public String getCreatedDateFormatted()
	{
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSX");
		return sdf.format(m_created_date);
	}
	
	
	private String		m_person_uuid = null;
	private String		m_message_uuid = null;
	private String		m_tenant_code = null;	
	private String		m_transaction_type = null;
	private long 		m_transaction_id;	
	private boolean 	m_succeeded;	
	private String 		m_post_back_url = null;
	private String 		m_post_back_request = null;
	private String 		m_post_back_response = null;	
	private String	 	m_exception = null;	
	private String 		m_be_response = null;	
	private Integer 	m_image_count = null;
	private String 		m_rejection_info = null;
	private String		m_template_uri = null;
	private Date		m_created_date = null;
	
}
