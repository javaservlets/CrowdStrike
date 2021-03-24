package com.crowdstrike.node;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;


@org.forgerock.openam.auth.node.api.Node.Metadata(outcomeProvider=
        ZeroTrust.MyOutcomeProvider.class,
        configClass=ZeroTrust.Config.class,
        tags={""} //to do
)
public class ZeroTrust extends AbstractDecisionNode {
    private final Logger DEBUG = LoggerFactory.getLogger(ZeroTrust.class);
    private final CoreWrapper coreWrapper;
    private final Config config;

    private final Logger logger=LoggerFactory.getLogger(ZeroTrust.class);
    int OVERALL_SCORE; // we'll parse a crowdstrike jot to get this val

    public interface Config {
        @Attribute(order=100)
        default int THRESHOLD() {
            return 50;
        }
    }

    @com.google.inject.Inject
    public ZeroTrust(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config=config;
        this.coreWrapper=coreWrapper;
    }


    @Override
    public Action process(TreeContext context) {
        Action action=null;
        try {
            String jwt=context.sharedState.get("jwt").asString();
            if (jwt == null) {
                log("No jwt was found by the time we got here.");
                action=goTo(MyOutcome.COMPLIANT).build();
            }

            JWebToken decoded=new JWebToken(jwt);
            OVERALL_SCORE=decoded.getOverallScore();
            log("overall: " + OVERALL_SCORE);

        } catch (Exception e) {
            log("jwt/scoring e: " + e);
        }

        try {
            if ((config.THRESHOLD()) > OVERALL_SCORE) {
                log("CrowdStrike threshold exceeded: ");
                action=goTo(MyOutcome.COMPLIANT).build();
            } else {
                log("CrowdStrike overall threshold not met: ");
                action=goTo(MyOutcome.NONCOMPLIANT).build();
            }
        } catch (Exception e) {
            log("comparing vals e: " + e);
        } finally {
            return action;

        }
    }

    public enum MyOutcome {
        COMPLIANT,
        NONCOMPLIANT,
        UNKNOWN
    }

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
        System.out.println("authnode: " + str);
        DEBUG.error("authnode: " + str);
    }


}


