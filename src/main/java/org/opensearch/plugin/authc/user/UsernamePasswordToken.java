/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensearch.plugin.authc.user;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Represents a username and password token for authentication.
 * Provides utilities for parsing basic authentication headers from REST requests.
 */
public class UsernamePasswordToken {
    /**
     * Constant for the username field.
     */
    public static final String USERNAME          = "username";
    /**
     * Constant for the Basic authentication prefix.
     */
    public static final String BASIC_AUTH_PREFIX = "Basic ";
    /**
     * Constant for the Authorization header name.
     */
    public static final String BASIC_AUTH_HEADER = "Authorization";

    private String username;
    private String password;

    /**
     * Constructs a new {@code UsernamePasswordToken} with the given username and password.
     *
     * @param username The username.
     * @param password The password.
     */
    public UsernamePasswordToken(String username, String password) {
        this.username = username;
        this.password = password;
    }

    /**
     * Parses a {@code UsernamePasswordToken} from the Authorization header of a {@link RestRequest}.
     * It expects a Basic authentication scheme.
     *
     * @param request The {@link RestRequest} from which to parse the token.
     * @return A {@code UsernamePasswordToken} if successful, or {@code null} if the header is missing or malformed.
     * @throws OpenSearchStatusException If parsing the authentication string fails.
     */
    public static UsernamePasswordToken parseToken(RestRequest request) {
        Map<String, List<String>> headers = request.getHeaders();

        if (MapUtils.isEmpty(headers)) {
            return null;
        }

        List<String> authStrs = headers.get(BASIC_AUTH_HEADER);

        if (CollectionUtils.isEmpty(authStrs)) {
            return null;
        }

        String authStr = authStrs.get(0);

        if (StringUtils.isEmpty(authStr)) {
            return null;
        }

        String userPass;

        try {
            userPass = new String(Base64.getUrlDecoder().decode(authStr.substring(BASIC_AUTH_PREFIX.length())),
                    StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new OpenSearchStatusException("Error: Failed to parse user authentication.", RestStatus.UNAUTHORIZED, e);
        }

        int i = StringUtils.indexOf(userPass, ':');

        if (i <= 0) {
            throw new OpenSearchStatusException("Error: Parse user authentication to get the wrong userPass[{}].", RestStatus.UNAUTHORIZED, userPass);
        }

        return new UsernamePasswordToken(StringUtils.substring(userPass, 0, i), StringUtils.substring(userPass, i + 1, userPass.length()));
    }

    /**
     * Returns the username.
     *
     * @return The username.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets the username.
     *
     * @param username The username to set.
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Returns the password.
     *
     * @return The password.
     */
    public String getPassword() {
        return password;
    }

    /**
     * Sets the password.
     *
     * @param password The password to set.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String toString() {
        return "UsernamePasswordToken [username=" + username + ", password=" + "******" + "]";
    }
}