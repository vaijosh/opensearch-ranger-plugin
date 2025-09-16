/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.opensearch.rangerauthorizer;

import org.apache.hadoop.conf.Configuration;
import org.apache.ranger.audit.model.AuthzAuditEvent;
import org.apache.ranger.plugin.audit.RangerMultiResourceAuditHandler;
import org.apache.ranger.plugin.policyengine.RangerAccessRequest;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;

import java.util.Arrays;
import java.util.List;

/**
 * An audit handler for Ranger OpenSearch plugin that extends {@link RangerMultiResourceAuditHandler}.
 * It manages the auditing of authorization events in OpenSearch, with specific logic
 * to exclude certain users or audit events to prevent recursive logging.
 */
public class RangerOpensearchAuditHandler extends RangerMultiResourceAuditHandler {
    private static final String PROP_OS_PLUGIN_AUDIT_EXCLUDED_USERS = "ranger.opensearch.plugin.audit.excluded.users";
    private static final String PROP_OS_PLUGIN_AUDIT_INDEX = "xasecure.audit.destination.opensearch.index";

    private final String       indexName;
    private final List<String> excludeUsers;

    /**
     * Constructs a new {@code RangerOpensearchAuditHandler} with the given configuration.
     * Initializes the audit index name and the list of excluded users from the configuration.
     *
     * @param config The Hadoop configuration object containing audit properties.
     */
    public RangerOpensearchAuditHandler(Configuration config) {
        String osUser          = "org/opensearch";
        String excludeUserList = config.get(PROP_OS_PLUGIN_AUDIT_EXCLUDED_USERS, osUser);

        excludeUsers = Arrays.asList(excludeUserList.split(","));
        indexName    = config.get(PROP_OS_PLUGIN_AUDIT_INDEX, "ranger_audits");
    }

    @Override
    public void processResult(RangerAccessResult result) {
        // We don't audit "allowed" operation for user "opensearch" on index "ranger_audits" to avoid recursive
        // logging due to updated of ranger_audits index by opensearch plugin's audit creation.
        if (!isAuditingNeeded(result)) {
            return;
        }

        AuthzAuditEvent auditEvent = super.getAuthzEvents(result);

        super.logAuthzAudit(auditEvent);

        //XXX:TODO: Can we improve this and flush events based on flush interval or some other events?
        super.flushAudit();
    }

    /**
     * Determines if auditing is needed for a given Ranger access result.
     * Auditing is not needed if the operation is allowed, the resource is the audit index,
     * and the requesting user is in the excluded users list.
     *
     * @param result The {@link RangerAccessResult} to check.
     * @return {@code true} if auditing is needed, {@code false} otherwise.
     */
    private boolean isAuditingNeeded(final RangerAccessResult result) {
        boolean                  ret          = true;
        boolean                  isAllowed    = result.getIsAllowed();
        RangerAccessRequest      request      = result.getAccessRequest();
        RangerAccessResourceImpl resource     = (RangerAccessResourceImpl) request.getResource();
        String                   resourceName = (String) resource.getValue("index");
        String                   requestUser  = request.getUser();

        if (resourceName != null && resourceName.equals(indexName) && excludeUsers.contains(requestUser) && isAllowed) {
            ret = false;
        }

        return ret;
    }
}