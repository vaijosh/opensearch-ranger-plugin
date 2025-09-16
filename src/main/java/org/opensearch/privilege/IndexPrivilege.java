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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.opensearch.privilege;

import java.util.List;

/**
 * IndexPrivilege
 */
public class IndexPrivilege {
    private String       privilege;
    private List<String> actions;

    /**
     *
     * @param privilege - Privilege
     * @param actions - List of Actions
     */
    public IndexPrivilege(String privilege, List<String> actions) {
        super();

        this.privilege = privilege;
        this.actions   = actions;
    }

    /**
     *
     * @return Privilege
     */
    public String getPrivilege() {
        return privilege;
    }

    /**
     *
     * @param privilege - Privilege to set
     */
    public void setPrivilege(String privilege) {
        this.privilege = privilege;
    }

    /**
     *
     * @return List of Actions
     */
    public List<String> getActions() {
        return actions;
    }

    /**
     *
     * @param actions - List of Actions to set
     */
    public void setActions(List<String> actions) {
        this.actions = actions;
    }

    /**
     *
     * @return String representation of Privilege and actions
     */
    @Override
    public String toString() {
        return "IndexPrivilege [privilege=" + privilege + ", actions=" + actions + "]";
    }
}
