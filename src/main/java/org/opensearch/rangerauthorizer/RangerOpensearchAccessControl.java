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

package org.opensearch.rangerauthorizer;

import java.util.List;

/**
 * Interface for checking access control permissions in OpenSearch using Ranger.
 */
public interface RangerOpensearchAccessControl {
    /**
     * Check permission for user to perform an action on an OpenSearch index.
     *
     * @param user The user performing the request.
     * @param groups The groups to which the user belongs.
     * @param index The OpenSearch index on which the action is performed.
     * @param action The operation type (e.g., "read", "write").
     * @param clientIPAddress The client's IP address.
     * @return {@code true} if the permission is granted, {@code false} otherwise.
     */
    boolean checkPermission(String user, List<String> groups, String index, String action, String clientIPAddress);
}