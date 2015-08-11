package net.shibboleth.idp.oidc.flow;

import org.springframework.webflow.execution.Event;

public enum Events {
    SessionNotFound,
    SessionFound,
    Success,
    Failure,
    Proceed;

    private Events() {
    }

    public String id() {
        return this.name().substring(0, 1).toLowerCase() + this.name().substring(1);
    }

    public Event event(Object source) {
        return new Event(source, this.id());
    }
}
