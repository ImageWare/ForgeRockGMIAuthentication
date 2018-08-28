package com.iws.forgerock.gmi.entity;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;

import javax.xml.bind.annotation.XmlRootElement;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 *
 */
@XmlRootElement
public class Message
{
	private static final String TENANT_CONSTANT = "tenant";
	private static final String TEMPLATE_CONSTANT = "template";
	private static final String APPLICATION_CONSTANT = "app";

	public Message()
	{
		
	}
	
	public Message(String message_id)
	{
		setMessageId(message_id);
	}

	public String getMessageId()
	{
		return m_message_id;
	}
	
	public void setMessageId(String message_id)
	{
		m_message_id = message_id;
	}
	
	public String getTemplate()
	{
		return m_template;
	}
	public String getTemplateWithoutApp()
	{
		if (null != m_template)
		{
			// return the template without the app in it
			
			String template_without_app = new String(m_template);
		
			StringTokenizer tok = new StringTokenizer(m_template, "/");
			
			String app_code = null;
			try
			{
				while (tok.hasMoreTokens())
				{
					String path_element = tok.nextToken();
					if (path_element == null)
					{
						break;
					}
					
					else if (path_element.equals(APPLICATION_CONSTANT))
					{
						// get the application code
						app_code = tok.nextToken();
					}
				}
			}
			catch (NoSuchElementException nsex)
			{
				// do nothing. 
			}
			
			if (null != app_code)
			{
				template_without_app = template_without_app.replace("/"+APPLICATION_CONSTANT+"/"+app_code, "");
			}
			
			return template_without_app;
			
		}
		
		return m_template;
	}
	
	public void setTemplate(String template)
	{
		m_template = template;
	}
	
	public Map<String, Object> getMetadata()
	{
		return m_metadata;
	}
	
	public void setMetadata(Map<String, Object> metadata)
	{
		m_metadata = metadata;
	}
	
	public String getPostbackUrl()
	{
		return m_postback_url;
	}
	
	public void setPostbackUrl(String postback_url)
	{
		m_postback_url = postback_url;
	}
	
	
	public Integer getExpiresIn()
	{
		return m_expires_in;
	}
	
	public void setExpiresIn(Integer seconds)
	{
		m_expires_in = seconds;
	}
	public Date getCreatedDate()
	{
		return m_created_date;
	}
	public void setCreatedDate(Date created_date)
	{
		m_created_date = created_date;
	}
	public Date getExpireDate()
	{
		return m_expire_date;
	}
	public void setExpireDate(Date created_date)
	{
		m_expire_date = created_date;
	}
	public String getExpireDateFormatted()
	{
		if (null != m_expire_date)
		{	
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSX");
			return sdf.format(m_expire_date);
		}
		else
		{
			return null;
		}
	}
	
	public Integer getMaxResponseAttempts()
	{
		return m_max_response_attempts;
	}

	public void setMaxResponseAttempts(Integer max_response_attempts)
	{
		m_max_response_attempts = max_response_attempts;
	}
	
	
	@JsonIgnore
	public String getTemplateCode()
	{
		StringTokenizer tok = new StringTokenizer(m_template, "/");
		
		try
		{
			while (tok.hasMoreTokens())
			{
				String path_element = tok.nextToken();
				if (path_element == null)
				{
					break;
				}
				
				if (path_element.equals(TEMPLATE_CONSTANT))
				{
					// get the template code
					return tok.nextToken();
				}
			}
		}
		catch (NoSuchElementException nsex)
		{
			// do nothing. 
		}
		return null;
	}


	@JsonIgnore
	public String getApplicationCode()
	{
		StringTokenizer tok = new StringTokenizer(m_template, "/");
		
		try
		{
			while (tok.hasMoreTokens())
			{
				String path_element = tok.nextToken();
				if (path_element == null)
				{
					break;
				}
				
				if (path_element.equals(APPLICATION_CONSTANT))
				{
					// get the application code
					return tok.nextToken();
				}
			}
		}
		catch (NoSuchElementException nsex)
		{
			// do nothing. 
		}
		return "GoVerifyID"; //TODO: hardcoded, but does this matter?
	}
	
	@JsonIgnore
	public String getTenantCode()
	{
		StringTokenizer tok = new StringTokenizer(m_template, "/");
		
		try
		{
			while (tok.hasMoreTokens())
			{
				String path_element = tok.nextToken();
				if (path_element == null)
				{
					break;
				}
				
			    if (path_element.equals(TENANT_CONSTANT))
				{
					// get the tenant code
					return tok.nextToken();
				}
			}
		}
		catch (NoSuchElementException nsex)
		{
			// do nothing.  this is expected.
		}
		return null;
	}
	
	public void setRequired(List<String> required)
	{
		if (required == null)
		{
			m_required = null;
		}
		else
		{
			m_required = new ArrayList<String>(required);
		}
	}
	
	public List<String> getRequired()
	{
		return m_required;
	}
	
	public void setOptional(List<String> optional)
	{
		if (optional == null)
		{
			m_optional = null;
		}
		else
		{
			m_optional = new ArrayList<String>(optional);
		}
	}
	
	public List<String> getOptional()
	{
		return m_optional;
	}

	
	private String	m_message_id = null;
	private String	m_template = null;
	private Map<String, Object>		m_metadata = null;
	private String	m_postback_url = null;
	private Integer	m_expires_in = null;
	private Date	m_created_date = null;
	private Date	m_expire_date = null;
	private Integer	m_max_response_attempts = null;
	
	// these values are populated on GET calls only.  They come from the MessageTemplate.
	// at some point we may want to allow override for individual message sends, but not now.
	private List<String>	m_required = null;
	private List<String>	m_optional = null;

}
