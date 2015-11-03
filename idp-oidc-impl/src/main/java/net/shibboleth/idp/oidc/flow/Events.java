package net.shibboleth.idp.oidc.flow;

import org.springframework.webflow.core.collection.AttributeMap;
import org.springframework.webflow.execution.Event;

/**
 * TDescribes webflow event ids
 * that can be produced as outcome
 * of actions.
 */
public enum Events {
    /**
     * Indicates a missing authentication session.
     */
    SessionNotFound,
    /**
     * Indicates session is found.
     */
    SessionFound,
    /**
     * The Success event.
     */
    Success,
    /**
     * The Failure event.
     */
    Failure,

    /**
     * The BadRequest event.
     */
    BadRequest,

    /**
     * The ClientNotFound event.
     */
    ClientNotFound,

    /**
     * The Redirect event.
     */
    Redirect,

    /**
     * The Proceed event.
     */
    Proceed;

    /**
     * Returns the id of the enum off of its name.
     *
     * @return the string
     */
    public String id() {
        return name().substring(0, 1).toLowerCase() + name().substring(1);
    }

    /**
     * Builds the event based on the enum id.
     *
     * @param source the source
     * @return the event
     */
    public Event event(final Object source) {
        return new Event(source, id());
    }

    /**
     * Builds the event based on the enum id.
     *
     * @param source the source
     * @param attributes the attributes
     * @return the event
     */
    public Event event(final Object source, final AttributeMap<Object> attributes) {
        return new Event(source, id(), attributes);
    }
}
