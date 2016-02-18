/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements. See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.shibboleth.idp.oidc;

/**
 * The type Oidc exception.
 */
public class OIDCException extends RuntimeException {

    /**
     * Instantiates a new Oidc exception.
     */
    public OIDCException() {
    }

    /**
     * Instantiates a new Oidc exception.
     *
     * @param message the message
     */
    public OIDCException(final String message) {
        super(message);
    }

    /**
     * Instantiates a new Oidc exception.
     *
     * @param message the message
     * @param cause   the cause
     */
    public OIDCException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Instantiates a new Oidc exception.
     *
     * @param cause the cause
     */
    public OIDCException(final Throwable cause) {
        super(cause);
    }

    /**
     * Instantiates a new Oidc exception.
     *
     * @param message            the message
     * @param cause              the cause
     * @param enableSuppression  the enable suppression
     * @param writableStackTrace the writable stack trace
     */
    public OIDCException(final String message, final Throwable cause, final boolean enableSuppression,
                         final boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
