package com.crowdstrike.node;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.List;

@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = ZeroTrust.Config.class)
public class ZeroTrust extends AbstractDecisionNode {
    private final CoreWrapper coreWrapper;
    private final Config config;

    private final Logger logger = LoggerFactory.getLogger(ZeroTrust.class);
    int OVERALL_SCORE; // we'll parse a crowdstrike jot to get this val

    public interface Config {
        @Attribute(order = 100)
        default int THRESHOLD() { return 50; }
    }

    @com.google.inject.Inject
    public ZeroTrust(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config=config;
        this.coreWrapper=coreWrapper;
    }


    @Override
    public Action process(TreeContext context) {
        Action action=null;
        String jwt = context.sharedState.get("jwt").asString();
        if (jwt == null) {
            log("No jwt was found by the time we got here.");
            return goTo(false).build();
        }

        try {
            JWebToken decoded=new JWebToken(jwt);
             OVERALL_SCORE = decoded.getOverallScore();
        } catch (Exception e) {
            log("scoring e: " + e);
        }

        if (config.THRESHOLD() >  OVERALL_SCORE) {
            log("CrowdStrike threshold exceeded: ");
            action=goTo(MyOutcome.COMPLIANT).build();
        } else {
            log("CrowdStrike overall threshold not met: ");
            action=goTo(MyOutcome.NONCOMPLIANT).build();
        }
        return action;
    }

    public enum MyOutcome {
        COMPLIANT,
        NONCOMPLIANT,
        UNKNOWN}

    private Action.ActionBuilder goTo(MyOutcome outcome) {
        return Action.goTo(outcome.name());
    }

    public static class MyOutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            return ImmutableList.of(
                    new Outcome(MyOutcome.COMPLIANT.name(), "Compliant"),
                    new Outcome(MyOutcome.NONCOMPLIANT.name(), "Non-Compliant"),
                    new Outcome(MyOutcome.UNKNOWN.name(), "Unknown"));
        }
    }

    private void log(String str) {
        logger.debug("+++ crowdstrike msg: " + str + "\r\n");
    }


}


