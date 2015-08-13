/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.shibboleth.idp.oidc.flow;

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
    public Event event(Object source) {
        return new Event(source, id());
    }
}
