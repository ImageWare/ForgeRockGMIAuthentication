package com.iws.forgerock;

import java.util.List;

import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.util.i18n.PreferredLocales;

public class ValidateUserOutcomeProvider implements OutcomeProvider 
{
	
	public static final String UNANSWERED = "Unanswered";
	
	@Override
    public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) throws NodeProcessException
    {
        //ResourceBundle bundle = locales.getBundleInPreferredLocale(LdapDecisionNode.BUNDLE,
        //        LdapOutcomeProvider.class.getClassLoader());
        return ImmutableList.of(
                new Outcome("True", "True"),
                new Outcome("False", "False"),
                new Outcome("Unanswered", "Unanswered"));
    }

}
