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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.thirdparty.com.google.common.collect.Sets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.ranger.audit.provider.MiscUtil;
import org.apache.ranger.plugin.policyengine.RangerAccessRequestImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResourceImpl;
import org.apache.ranger.plugin.policyengine.RangerAccessResult;
import org.apache.ranger.plugin.service.RangerBasePlugin;
import org.opensearch.client.OpensearchResourceMgr;
import org.opensearch.privilege.IndexPrivilegeUtils;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Implements OpenSearch access control using Apache Ranger.
 * This class acts as an authorizer, checking permissions for user actions on OpenSearch indices.
 */
public class RangerOpensearchAuthorizer implements RangerOpensearchAccessControl {
    private static final Logger LOG = LogManager.getLogger(RangerOpensearchAccessControl.class);

    private static volatile RangerOpensearchInnerPlugin opensearchPlugin;

    /**
     * Constructs a new {@code RangerOpensearchAuthorizer} and initializes the Ranger plugin.
     */
    public RangerOpensearchAuthorizer() {
        LOG.debug("==> RangerOpensearchAuthorizer.RangerOpensearchAuthorizer()");
        this.init();
        LOG.debug("<== RangerOpensearchAuthorizer.RangerOpensearchAuthorizer()");
    }

    /**
     * Initializes the Ranger OpenSearch plugin.
     * Ensures that the plugin is initialized only once.
     */
    private void init() {
        LOG.debug("==> init()");
        RangerOpensearchInnerPlugin plugin = opensearchPlugin;
        if (plugin == null) {
            synchronized (RangerOpensearchAuthorizer.class) {
                plugin = opensearchPlugin;

                if (plugin == null) {
                    plugin = new RangerOpensearchInnerPlugin();

                    plugin.init();

                    opensearchPlugin = plugin;
                }
            }
        }
        LOG.debug("<== RangerOpensearchAuthorizer.init()");
    }

    @Override
    public boolean checkPermission(String user, List<String> groups, String index, String action, String clientIPAddress) {
        LOG.debug("==> RangerOpensearchAuthorizer.checkPermission( user={}, groups={}, index={}, action={}, clientIPAddress={})", user, groups, index, action, clientIPAddress);

        boolean ret = false;

        if (opensearchPlugin != null) {
            if (null == groups) {
                groups = new ArrayList<>(MiscUtil.getGroupsForRequestUser(user));
            }

            String                           privilege = IndexPrivilegeUtils.getPrivilegeFromAction(action);
            RangerOpensearchAccessRequest request   = new RangerOpensearchAccessRequest(user, groups, index, privilege, clientIPAddress);
            RangerAccessResult               result    = opensearchPlugin.isAccessAllowed(request);

            if (result != null && result.getIsAllowed()) {
                ret = true;
            }
        }

        LOG.debug("<== RangerOpensearchAuthorizer.checkPermission(): result={}", ret);

        return ret;
    }

    /**
     * Inner plugin class for Ranger OpenSearch, extending {@link RangerBasePlugin}.
     * This class handles the initialization of the Ranger service and sets up the audit handler.
     */
    static class RangerOpensearchInnerPlugin extends RangerBasePlugin {
        public RangerOpensearchInnerPlugin() {
            // Note: This is important.
            // The Ranger classes uses serviceType and appID to determine config file. There are case-sensitive
            // If you don't specify appID, the configFile name will be ranger-<ServiceType>-<Opensearch>-<configFile>.xml
            // If you specify Apo ID, its ranger-<serviceName>-<configFile>.xml
            super("opensearch", "opensearch");
        }

        @Override
        public void init() {
            super.init();
            RangerOpensearchAuditHandler auditHandler = new RangerOpensearchAuditHandler(getConfig());
            super.setResultProcessor(auditHandler);
        }
    }

    /**
     * Represents an OpenSearch resource for Ranger access control.
     * It extends {@link RangerAccessResourceImpl} and sets the resource value as an index.
     */
    static class RangerOpensearchResource extends RangerAccessResourceImpl {
        /**
         * Constructs a new {@code RangerOpensearchResource} with the specified index.
         * If the index is empty, it defaults to "*".
         *
         * @param index The OpenSearch index name.
         */
        public RangerOpensearchResource(String index) {
            if (StringUtils.isEmpty(index)) {
                index = "*";
            }

            setValue(OpensearchResourceMgr.INDEX, index);
        }
    }

    /**
     * Represents an access request for OpenSearch in Ranger.
     * It extends {@link RangerAccessRequestImpl} and encapsulates user, groups, index, privilege, and client IP.
     */
    static class RangerOpensearchAccessRequest extends RangerAccessRequestImpl {
        /**
         * Constructs a new {@code RangerOpensearchAccessRequest}.
         *
         * @param user The user making the request.
         * @param groups The list of groups the user belongs to.
         * @param index The index being accessed.
         * @param privilege The privilege being requested (e.g., "read", "write").
         * @param clientIPAddress The IP address of the client.
         */
        public RangerOpensearchAccessRequest(String user, List<String> groups, String index, String privilege, String clientIPAddress) {
            super.setUser(user);

            if (CollectionUtils.isNotEmpty(groups)) {
                super.setUserGroups(Sets.newHashSet(groups));
            }

            super.setResource(new RangerOpensearchResource(index));
            super.setAccessType(privilege);
            super.setAction(privilege);
            super.setClientIPAddress(clientIPAddress);
            super.setAccessTime(new Date());
        }
    }
}