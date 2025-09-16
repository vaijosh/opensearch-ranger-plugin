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

package org.opensearch.client;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.ranger.plugin.client.BaseClient;
import org.apache.ranger.plugin.client.HadoopException;
import org.apache.ranger.plugin.util.PasswordUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.ws.rs.core.MediaType;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.PrivilegedAction;
import java.util.*;

/**
 * Client class for interacting with OpenSearch services.
 * This class extends {@link BaseClient} to provide core client functionalities
 * and adds OpenSearch-specific operations.
 */
public class OSClient extends BaseClient {
    private static final Logger LOG = LoggerFactory.getLogger(OSClient.class);

    private static final String OPENSEARCH_INDEX_API_ENDPOINT = "/_all";

    private final String opensearchUrl;
    private final String userName;
    private final String password;

    /**
     * Constructs a new {@code OpensearchClient} with the specified service name and configurations.
     *
     * @param serviceName The name of the service.
     * @param configs A map of configuration properties for the client.
     */
    public OSClient(String serviceName, Map<String, String> configs) {
        super(serviceName, configs, "opensearch-client");

        this.opensearchUrl = configs.get("opensearch.url");
        this.userName         = configs.get("username");
        this.password         = configs.get("password");

        if (StringUtils.isEmpty(this.opensearchUrl)) {
            LOG.error("No value found for configuration 'opensearch.url'. Opensearch resource lookup will fail.");
        }

        if (StringUtils.isEmpty(this.userName)) {
            LOG.error("No value found for configuration 'username'. Opensearch resource lookup will fail.");
        }

        LOG.debug("Opensearch client is build with url: [{}], user: [{}].", this.opensearchUrl, this.userName);
    }

    /**
     * Performs a connection test to the OpenSearch service using the given configurations.
     *
     * @param serviceName The name of the service.
     * @param configs A map of configuration properties for the client.
     * @return A map containing the connectivity status and a message.
     */
    public static Map<String, Object> connectionTest(String serviceName, Map<String, String> configs) {
        OSClient OSClient = getOpensearchClient(serviceName, configs);
        List<String>        indexList           = OSClient.getIndexList(null, null);

        boolean connectivityStatus = false;

        if (CollectionUtils.isNotEmpty(indexList)) {
            LOG.debug("ConnectionTest list size {} opensearch indices.", indexList.size());

            connectivityStatus = true;
        }

        Map<String, Object> responseData = new HashMap<>();

        if (connectivityStatus) {
            String successMsg = "ConnectionTest Successful.";

            BaseClient.generateResponseDataMap(true, successMsg, successMsg, null, null, responseData);
        } else {
            String failureMsg = "Unable to retrieve any opensearch indices using given parameters.";

            BaseClient.generateResponseDataMap(false, failureMsg, failureMsg + DEFAULT_ERROR_MESSAGE, null, null, responseData);
        }

        return responseData;
    }

    /**
     * Returns an {@code OpensearchClient} instance for the specified service and configurations.
     *
     * @param serviceName The name of the service.
     * @param configs A map of configuration properties for the client.
     * @return An instance of {@code OpensearchClient}.
     * @throws HadoopException If the connection configuration is empty.
     */
    public static OSClient getOpensearchClient(String serviceName, Map<String, String> configs) {
        OSClient OSClient;

        LOG.debug("Getting opensearchClient for datasource: {}", serviceName);

        if (MapUtils.isEmpty(configs)) {
            String msgDesc = "Could not connect opensearch as connection configMap is empty.";

            LOG.error(msgDesc);

            HadoopException hdpException = new HadoopException(msgDesc);

            hdpException.generateResponseDataMap(false, msgDesc, msgDesc + DEFAULT_ERROR_MESSAGE, null, null);

            throw hdpException;
        } else {
            OSClient = new OSClient(serviceName, configs);
        }

        return OSClient;
    }

    /**
     * Retrieves a list of indices based on a matching pattern and an existing list of indices.
     * This method filters or expands the existing indices based on the provided matching string.
     *
     * @param indexMatching The pattern to match indices against (e.g., "logstash-*" or "my_index"). Can be null for all indices.
     * @param existingIndices A list of indices that currently exist or are known. Can be null.
     * @return A {@code List} of strings representing the matched and filtered indices. Returns an empty list if no indices are found or if the subject is null.
     */
    public List<String> getIndexList(final String indexMatching, final List<String> existingIndices) {
        LOG.debug("Get opensearch index list for indexMatching: {}, existingIndices: {}", indexMatching, existingIndices);

        Subject subj = getLoginSubject();

        if (subj == null) {
            return Collections.emptyList();
        }

        List<String> ret = Subject.doAs(subj, (PrivilegedAction<List<String>>) () -> {
            String indexApi;

            if (StringUtils.isNotEmpty(indexMatching)) {
                indexApi = '/' + indexMatching;

                if (!indexApi.endsWith("*")) {
                    indexApi += "*";
                }
            } else {
                indexApi = OPENSEARCH_INDEX_API_ENDPOINT;
            }

            ClientResponse      response        = getClientResponse(opensearchUrl, indexApi, userName, password);
            Map<String, Object> index2detailMap = getOpensearchResourceResponse(response, new TypeToken<HashMap<String, Object>>() {}.getType());

            if (MapUtils.isEmpty(index2detailMap)) {
                return Collections.emptyList();
            }

            Set<String> indexResponses = index2detailMap.keySet();

            if (CollectionUtils.isEmpty(indexResponses)) {
                return Collections.emptyList();
            }

            return filterResourceFromResponse(indexMatching, existingIndices, new ArrayList<>(indexResponses));
        });

        LOG.debug("Get opensearch index list result: {}", ret);

        return ret;
    }

    /**
     * Retrieves a client response from the OpenSearch API endpoint.
     *
     * @param opensearchUrl The base URL of the OpenSearch service.
     * @param opensearchApi The specific API endpoint to call.
     * @param userName The username for authentication.
     * @param password The password for authentication (can be encrypted).
     * @return A {@code ClientResponse} object.
     */
    private static ClientResponse getClientResponse(String opensearchUrl, String opensearchApi, String userName, String password) {
        String[] opensearchUrls = opensearchUrl.trim().split("[,;]");

        if (ArrayUtils.isEmpty(opensearchUrls)) {
            return null;
        }

        ClientResponse response = null;
        Client         client   = Client.create();

        for (String currentUrl : opensearchUrls) {
            if (StringUtils.isBlank(currentUrl)) {
                continue;
            }

            String url = currentUrl.trim() + opensearchApi;

            try {
                response = getClientResponse(url, client, userName, password);

                if (response != null) {
                    if (response.getStatus() == HttpStatus.SC_OK) {
                        break;
                    } else {
                        response.close();
                    }
                }
            } catch (Throwable t) {
                String msgDesc = "Exception while getting opensearch response, opensearchUrl: " + url;

                LOG.error(msgDesc, t);
            }
        }

        client.destroy();

        return response;
    }

    /**
     * Decrypts the given encrypted password. If decryption fails or password is null, returns the original password.
     *
     * @param encryptedPwd The encrypted password string.
     * @return The decrypted password, or the original string if decryption fails or input is null.
     */
    private static String decryptPass(String encryptedPwd) {
        String password     = null;
        if (encryptedPwd != null) {
            try {
                password = PasswordUtils.decryptPassword(encryptedPwd);
            } catch (Exception ex) {
                LOG.info("Password decryption failed; trying connection with received password string");

                password = null;
            } finally {
                if (password == null) {
                    password = encryptedPwd;
                }
            }
        } else {
            LOG.info("Password decryption failed: no password was configured");
        }
        return password;
    }

    /**
     * Retrieves a client response from the specified URL using the provided client, username, and password.
     *
     * @param url The full URL to send the request to.
     * @param client The Jersey client instance.
     * @param userName The username for basic authentication.
     * @param password The password for basic authentication (can be encrypted).
     * @return A {@code ClientResponse} object.
     */
    private static ClientResponse getClientResponse(String url, Client client, String userName, String password) {
        LOG.debug("getClientResponse():calling {}", url);
        String decryptedPass = decryptPass(password);
        String auth = userName + ":" + decryptedPass;
        byte[] encodedAuth = Base64.getEncoder().encode(auth.getBytes(StandardCharsets.UTF_8));
        String encodedAuthStr = new String(encodedAuth,StandardCharsets.UTF_8);
        String authHeader = "Basic " + encodedAuthStr;
        ClientResponse response = client.resource(url).accept(MediaType.APPLICATION_JSON).header("userName", userName).header("Authorization", authHeader).get(ClientResponse.class);

        if (response != null) {
            LOG.debug("getClientResponse():response.getStatus()= {}", response.getStatus());

            if (response.getStatus() != HttpStatus.SC_OK) {
                LOG.warn("getClientResponse():response.getStatus()= {} for URL {}, failed to get opensearch resource list, response= {}", response.getStatus(), url, response.getEntity(String.class));
            }
        }

        return response;
    }

    /**
     * Parses the OpenSearch resource response from a {@code ClientResponse} object into the specified type.
     *
     * @param response The {@code ClientResponse} from the OpenSearch service.
     * @param type The {@code Type} to which the JSON response should be deserialized.
     * @param <T> The type of the resource to be returned.
     * @return The deserialized resource object.
     * @throws HadoopException If the response is invalid or an error occurs during processing.
     */
    private <T> T getOpensearchResourceResponse(ClientResponse response, Type type) {
        T resource;

        try {
            if (response != null && response.getStatus() == HttpStatus.SC_OK) {
                String jsonString = response.getEntity(String.class);
                Gson   gson       = new GsonBuilder().setPrettyPrinting().create();

                resource = gson.fromJson(jsonString, type);
            } else {
                String msgDesc = "Unable to get a valid response for " + "expected mime type : [" + MediaType.APPLICATION_JSON + "], opensearchUrl: " + opensearchUrl + " - got null response.";

                LOG.error(msgDesc);

                HadoopException hdpException = new HadoopException(msgDesc);

                hdpException.generateResponseDataMap(false, msgDesc, msgDesc + DEFAULT_ERROR_MESSAGE, null, null);

                throw hdpException;
            }
        } catch (HadoopException he) {
            throw he;
        } catch (Throwable t) {
            String msgDesc = "Exception while getting opensearch resource response, opensearchUrl: " + opensearchUrl;

            HadoopException hdpException = new HadoopException(msgDesc, t);

            LOG.error(msgDesc, t);

            hdpException.generateResponseDataMap(false, BaseClient.getMessage(t), msgDesc + DEFAULT_ERROR_MESSAGE, null, null);

            throw hdpException;
        } finally {
            if (response != null) {
                response.close();
            }
        }

        return resource;
    }

    /**
     * Filters a list of resource responses based on a matching pattern and existing resources.
     * Resources already in {@code existingResources} are excluded, and resources are filtered by {@code resourceMatching}.
     *
     * @param resourceMatching The pattern to match resources against. Can be empty or start with "*" to include all.
     * @param existingResources A list of resources to exclude from the result.
     * @param resourceResponses The list of resource responses to filter.
     * @return A new {@code List} of filtered resource strings.
     */
    private static List<String> filterResourceFromResponse(String resourceMatching, List<String> existingResources, List<String> resourceResponses) {
        List<String> resources = new ArrayList<>();

        for (String resourceResponse : resourceResponses) {
            if (CollectionUtils.isNotEmpty(existingResources) && existingResources.contains(resourceResponse)) {
                continue;
            }

            if (StringUtils.isEmpty(resourceMatching) || resourceMatching.startsWith("*") || resourceResponse.toLowerCase(Locale.ROOT).startsWith(resourceMatching.toLowerCase(Locale.ROOT))) {
                LOG.debug("filterResourceFromResponse(): Adding opensearch resource {}", resourceResponse);

                resources.add(resourceResponse);
            }
        }

        return resources;
    }
}